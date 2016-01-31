;;; cabledolphin.el --- capture Emacs network traffic  -*- lexical-binding: t; -*-

;; Copyright (C) 2016  Magnus Henoch

;; Author: Magnus Henoch <magnus.henoch@gmail.com>
;; Keywords: comm

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; Cabledolphin captures network traffic to and from Emacs Lisp
;; processes, and writes it into a PCAP file, which can be read by
;; tools such as tcpdump and Wireshark.
;;
;; Since Cabledolphin extracts the data on the Emacs Lisp level, it
;; writes the packet capture in cleartext even if the connection is
;; TLS-encrypted.
;;
;; While it doesn't get hold of actual packet headers, it synthesises
;; TCP/IP headers to the minimum extent required to keep Wireshark
;; happy.
;;
;; To start capturing packets for a certain connection, invoke
;; `cabledolphin-trace-existing-connection'.  To change the file that
;; data is written to, invoke `cabledolphin-set-pcap-file'.  To stop
;; capturing, invoke `cabledolphin-stop'.

;;; Code:

(require 'bindat)
(require 'seq)

(defvar cabledolphin-pcap-file nil
  "File to which captured data is appended.")

;; See pcap file format spec at
;; https://wiki.wireshark.org/Development/LibpcapFileFormat
(defconst cabledolphin--pcap-header-bindat-spec
  '(
    ;; Give magic number as a vector, so this works on 32-bit Emacsen.
    (magic-number vec 4 u8)
    (version-major u16)
    (version-minor u16)
    ;; thiszone is actually signed, but bindat doesn't support signed
    ;; integers.  Doesn't matter: we set it to 0.
    (thiszone u32)
    (sigfigs u32)
    (snaplen u32)
    (network u32))
  "Bindat spec for big-endian pcap file header.")

(defconst cabledolphin--pcap-packet-header-bindat-spec
  '(
    ;; Specify seconds in two 16-bit parts, for compatibility with 32-bit Emacsen.
    (ts-sec-high u16)
    (ts-sec-low u16)
    (ts-usec u32)
    (incl-len u32)
    (orig-len u32))
  "Bindat spec for big-endian pcap packet header.")

(defconst cabledolphin--ipv4-bindat-spec
  '((version-and-header-length u8)
    (dscp-ecn u8)
    (total-length u16)
    (identification u16)
    (flags-and-fragment-offset u16)
    (ttl u8)
    (protocol u8)
    (header-checksum u16)
    (src-addr vec 4 u8)
    (dest-addr vec 4 u8))
  "Bindat spec for IPv4 packet header, without options.")

(defconst cabledolphin--ipv6-bindat-spec
  '((version-etc u8)
    (fill 3)
    (payload-length u16)
    (next-header u8)
    (hop-limit u8)
    (src-addr vec 8 u16)
    (dest-addr vec 8 u16))
  "Bindat spec for IPv6 packet header.")

(defconst cabledolphin--tcp-bindat-spec
  '((src-port u16)
    (dest-port u16)
    (seq u32)
    (ack u32)
    (data-offset-and-reserved u8)
    (flags bits 1)
    (window-size u16)
    (checksum u16)
    (urgent-pointer u16))
  "Bindat spec for TCP header, without options.")

;;;###autoload
(defun cabledolphin-set-pcap-file (file)
  (interactive "FWrite data to pcap file: ")
  (setq cabledolphin-pcap-file file)

  ;; If the file doesn't exist, or is empty, we need to write a pcap
  ;; header.
  (let ((attributes (file-attributes file)))
    (when (or (null attributes)
	      (zerop (nth 7 attributes)))
      (with-temp-buffer
	(insert (bindat-pack cabledolphin--pcap-header-bindat-spec
			     '((magic-number . [#xa1 #xb2 #xc3 #xd4])
			       (version-major . 2)
			       (version-minor . 4)
			       (thiszone . 0)
			       (sigfigs . 0)
			       (snaplen . 65535)
			       ;; 101 is LINKTYPE_RAW, for raw IPv4/IPv6
			       (network . 101))))
	(let ((coding-system-for-write 'binary))
	  (write-region (point-min) (point-max) file nil :silent))))))

;;;###autoload
(defun cabledolphin-trace-existing-connection (process)
  (interactive
   (list
    (get-process
     (completing-read
      "Capture network traffic for: "
      (mapcar
       'process-name
       (cl-remove-if-not 'listp (process-list) :key 'process-contact))))))
  (unless cabledolphin-pcap-file
    (call-interactively 'cabledolphin-set-pcap-file))
  (process-put process :cabledolphin-traced t)
  (process-put process :cabledolphin-seq-in 0)
  (process-put process :cabledolphin-seq-out 0)
  (add-function :before (process-filter process) 'cabledolphin--filter)
  (advice-add 'process-send-string :before 'cabledolphin--process-send-string)
  (advice-add 'process-send-region :before 'cabledolphin--process-send-region))

(defun cabledolphin-stop ()
  (interactive)
  (advice-remove 'process-send-string 'cabledolphin--process-send-string)
  (advice-remove 'process-send-region 'cabledolphin--process-send-region)
  (dolist (process (process-list))
    (remove-function (process-filter process) 'cabledolphin--filter)))

(defun cabledolphin--filter (process data)
  (when (process-get process :cabledolphin-traced)
    (cabledolphin--write-packet
     process data
     :seq-key :cabledolphin-seq-in
     :from :remote
     :to :local)))

(defun cabledolphin--process-send-region (process start end)
  (when (process-get process :cabledolphin-traced)
    (cabledolphin--process-send-string process (buffer-substring start end))))

(defun cabledolphin--process-send-string (process data)
  (when (process-get process :cabledolphin-traced)
    (cabledolphin--write-packet
     process data
     :seq-key :cabledolphin-seq-out
     :from :local
     :to :remote)))

(cl-defun cabledolphin--write-packet
    (process data &key seq-key ((:from from-key)) ((:to to-key)))
  ;; Ensure that data is binary.  This is idempotent.
  (setq data (encode-coding-string data 'binary t))
  (with-temp-buffer
    (let* ((time (current-time))
	   (len (length data))
	   (contact (process-contact process t))
	   (from (plist-get contact from-key))
	   (to (plist-get contact to-key))
	   (seq (process-get process seq-key))
	   (ip-version
	    (if (= 9 (length from))
		6
	      4))
	   (len-with-tcp
	    (+ len (bindat-length cabledolphin--tcp-bindat-spec ())))
	   (total-len
	    (+ len-with-tcp
	       (if (= ip-version 6)
		   (bindat-length cabledolphin--ipv6-bindat-spec ())
		 (bindat-length cabledolphin--ipv4-bindat-spec ())))))
      
      (insert (bindat-pack cabledolphin--pcap-packet-header-bindat-spec
			   `((ts-sec-high . ,(nth 0 time))
			     (ts-sec-low . ,(nth 1 time))
			     (ts-usec . ,(nth 2 time))
			     (incl-len . ,total-len)
			     (orig-len . ,total-len))))

      ;; Create a fake IP header.
      (cl-case ip-version
	(4
	 (insert (bindat-pack cabledolphin--ipv4-bindat-spec
			      `((version-and-header-length . #x45)
				(total-length . ,total-len)
				(identification . 0)
				(flags-and-fragment-offset . 0)
				(ttl . 128)
				;; protocol 6 for TCP
				(protocol . 6)
				(header-checksum . 0)
				(src-addr . ,(seq-take from 4))
				(dest-addr . ,(seq-take to 4))))))
	(6
	 (insert (bindat-pack cabledolphin--ipv6-bindat-spec
			      `((version-etc . #x60)
				(payload-length . ,len-with-tcp)
				;; protocol 6 for TCP
				(next-header . 6)
				(hop-limit . 128)
				(src-addr . ,(seq-take from 8))
				(dest-addr . ,(seq-take to 8)))))))

      ;; Create a fake TCP header.
      (insert (bindat-pack cabledolphin--tcp-bindat-spec
			   `((src-port . ,(elt from (1- (length from))))
			     (dest-port . ,(elt to (1- (length to))))
			     (seq . ,seq)
			     (ack . 0)
			     (data-offset-and-reserved . #x50)
			     ;; set SYN and PSH
			     (flags . (3 4))
			     (window-size . 16384)
			     (checksum . 0)
			     (urgent-pointer . 0))))

      ;; Finally insert the actual data.
      (insert data)

      ;; Insert our sequence counter.
      (process-put process seq-key (+ seq len))

      (let ((coding-system-for-write 'binary))
	(write-region (point-min) (point-max) cabledolphin-pcap-file t :silent)))))

(provide 'cabledolphin)
;;; cabledolphin.el ends here
