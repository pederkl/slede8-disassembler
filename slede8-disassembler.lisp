;; Disassembler for the SLEDE8 binary format.
;; Copyright 2020 Peder O. Klingenberg
;; License: MIT

(defpackage #:slede8-disassembler
  (:use #:cl)
  (:export #:slede8-disassembler))

(in-package #:slede8-disassembler)

(defparameter *instructions*
  '((#x0 stopp decoder-none)
    (#x1 sett decoder-reg+byte)
    (#x2 sett decoder-reg+regbyte)
    (#x3 finn decoder-daddr)
    (#x4 ((#x0 . last)
	  (#x1 . lagr))
     decoder-reg)
    (#x5 ((#x0 . og)
	  (#x1 . eller)
	  (#x2 . xeller)
	  (#x3 . vskift)
	  (#x4 . hskift)
	  (#x5 . pluss)
	  (#x6 . minus))
     decoder-reg+reg)
    (#x6 ((#x0 . les)
	  (#x1 . skriv))
     decoder-reg)
    (#x7 ((#x0 . lik)
	  (#x1 . ulik)
	  (#x2 . me)
	  (#x3 . mel)
	  (#x4 . se)
	  (#x5 . sel))
     decoder-reg+reg)
    (#x8 hopp decoder-paddr)
    (#x9 bhopp decoder-paddr)
    (#xa tur decoder-paddr)
    (#xb retur decoder-none)
    (#xc nope decoder-none))
  "Format: ((<nib1> <instr> <argument-parse-function>)
            ...)
<instr> can be a mnemonic assembly instruction, or if the same
first nibble is common across several instructions, a list of
pairs: ((<nib2> . <mnemonic>)
        ...)
")

(defparameter *data-max-length* nil
  "Max bytes to have in a single data statement.
Limit is just to keep the generated source readable.
set to NIL for no limit.  This is applied prior to
label merging, so labels may further split the data
statements.")

(defvar *labels* nil
  "Debugging aid, after a run, this contins a list of pairs
((<label> . <addr>) ... )")

(define-condition invalid-address () ())

(defun slede8-disassembler (filename
			    &key
			      force-data-ranges
			      (output-stream *standard-output*)
			      (include-address-in-output t))
  "Disassembles the binary file FILENAME.  The disassembled program is printed
to OUTPUT-STREAM (default stdout).  If INCLUDE-ADDRESS-IN-OUTPUT is non-NIL,
the address of each instruction (in hex) is printed at the beginning of each
line.  FORCE-DATA-RANGES is a list of elements where each element is either a
pair of addresses (<lower-inclusive> . <upper-exclusive>) or a single
address <lower-inclusive> (with an implied upper bound of infinity),
indicating ranges of addresses that have been manually determined to contain
data, not code."
  (let* ((s8-data (get-s8-byte-list filename)))
    (multiple-value-bind (instruction-stream labels)
	(s8-disassemble s8-data force-data-ranges)
      (setq *labels* labels) ;; For easy access post-run.
      (let ((program (insert-labels instruction-stream labels)))
	(output-slede8 program output-stream include-address-in-output)))))

(defun get-s8-byte-list (filename)
  "Read bytes from filename, discard file header and return byte list."
  (with-open-file (s filename :element-type 'unsigned-byte)
    (let ((data (make-array (file-length s) :element-type 'unsigned-byte)))
      (read-sequence data s)
      (unless (equalp #(#x2E #x53 #x4C #x45 #x44 #x45 #x38) (subseq data 0 7)) ; ".SLEDE8"
	(error "Not a valid slede8 (.s8) binary file"))
      (coerce (subseq data 7) 'list))))

(defun s8-disassemble (s8-byte-list force-data-ranges)
  "Decode S8-BYTE-LIST into a stream of instructions and .DATA-statements,
honoring FORCE-DATA-RANGES.  Returns a list of instructions and a list of
detected labels, both in ascending address order."
  (let ((program-length (length s8-byte-list))
	program
	labels)
    (loop with data-array = nil
	  with s8-byte-list = s8-byte-list
	  with address = 0
	  with label-counter = 0
          for ibyte = (pop s8-byte-list)
	  for nib1 = (and ibyte (logand #x0f ibyte))
	  for nib2 = (and ibyte (ash ibyte -4))
	  for instr = (unless (address-in-ranges address force-data-ranges)
			(let ((i (cdr (assoc nib1 *instructions*))))
                          (when (consp (car i))
			    (setq i (copy-list i))
			    (setf (car i) (cdr (assoc nib2 (car i)))))
			  i))
	  for dbyte = (and instr (pop s8-byte-list))
	  for nib3 = (and dbyte (logand #x0f dbyte))
	  for nib4 = (and dbyte (ash dbyte -4))
	  while ibyte
	  if (or (not instr)  ;; Couldn't decode, so this is a data byte
		 (not dbyte)) 
	    do
	       (push ibyte data-array)
	       (incf address)
	       (when (and *data-max-length*
			  (<= *data-max-length* (length data-array)))
		 (push (append (list (- address (length data-array))
				     '.data)
			       (nreverse data-array))
		       program)
		 (setq data-array nil))
          else  ;; We may have an instruction
	  do
	     (handler-case
		 (multiple-value-bind (instruction target-address target-type)
		     (decode-instruction instr nib2 nib3 nib4)
		   (when data-array
		     (push (append (list (- address (length data-array))
					 '.data)
				   (nreverse data-array))
			   program)
		     (setq data-array nil))
		   (push (cons address instruction) program)
		   (incf address 2)
		   (when target-address
		     (when (< (1- program-length) target-address)
		       (signal 'invalid-address))
		     (let* ((existing-label (car (rassoc target-address labels)))
			    (label (or existing-label
				       (format nil "~a~d" target-type (incf label-counter)))))
		       (unless existing-label
			 (push (cons label target-address) labels))
		       (setf (second instruction) label))))
	       (invalid-address ()
		 ;; Tried to jump out of bounds, so this couldn't have
		 ;; been an instruction after all, must be data
		 (push ibyte data-array)
		 (incf address)
		 (when dbyte ;; put the second byte back.
		   (push dbyte s8-byte-list))))
          end	    
	  finally
	     (when data-array
               (push (append (list (- address (length data-array))
				   '.data)
			     (nreverse data-array))
		     program)
	       (setq data-array nil)))
    (values (nreverse program)
	    (sort labels #'< :key #'cdr)
	    program-length)))

(defun insert-labels (instruction-stream labels)
  "Merges INSTRUCTION-STREAM and LABELS, splitting .DATA statements in
INSTRUCTION-STREAM as necessary.  Returns the merged program."
  (loop with program = instruction-stream        
	with next-label = (pop labels)
	with data-stmt-length
	with address = 0
	for statement = (pop program)
	for disass-address = (and statement (pop statement))
	for stmt-length = (if (eq (car statement) '.data)
			      (length (cdr statement))
			      2)
	while statement
	unless (= address disass-address)
	  do (warn "Counted address ~x, received address ~x from disassembly. Statement ~s~%"
		   address disass-address statement)
	if (and next-label
		(= address (cdr next-label)))
	  collect (car next-label)
	  and do (setq next-label (pop labels))
	if (and next-label
		(< (cdr next-label) (+ address stmt-length)))
	  ;; data statement that needs to be split
	  do (setq data-stmt-length (- (cdr next-label)
				       address))
	  and collect (cons address
			    (subseq statement 0 (1+ ;; for the initial .data
						 data-stmt-length)))
	  and do (incf address data-stmt-length)
	  and collect (car next-label)
	  and do (setq next-label (pop labels))
		 (push (append (list address '.data) (subseq statement (1+ data-stmt-length))) program)
	else
	  ;; regular statement
	  collect (cons address statement)
	  and do (incf address stmt-length)))

(defun output-slede8 (program stream include-address)
  "Prints PROGRAM to STREAM, optionally with each line preceeded by its address.
Without address prefixes, output should be suitable to paste to
https://slede8.npst.no/"
  (loop for statement in program
	if (consp statement)
	  do (let ((address (pop statement)))
	       (when include-address
		 (format stream "~2,'0x: " address))
	       (format stream "~a " (car statement)))
	     (loop for (arg . rest) on (cdr statement)
		   if (numberp arg)
		     do (format stream "0x~2,'0x" arg)
		   else
		     do (format stream "~a" arg)
		   if rest
		     do (format stream ", "))
	else
	  do (format stream "~a:" statement)
	end
	do
	   (terpri stream)))

(defun address-in-ranges (address ranges)
  "Checks if ADDRESS falls within any of the RANGES.
Each range in RANGES is either a pair (lower-inclusive . upper-exclusive)
or a single address denoting the inclusive lower bound of an infinite range.
Returns non-NIL iff ADDRESS is part of any range."
  (loop for range in ranges
	do
	   (cond ((and (listp range)
		       (<= (car range) address (1- (cdr range))))
		  (return range))
		 ((and (numberp range)
		       (<= range address))
		  (return range)))))

(defun decode-instruction (instr nib2 nib3 nib4)
  "Parses the argument nibbles for a given instruction.
Returns two values. 1) A list (MNEMONIC [arg1 [arg2]]) for the instruction,
2) the address referenced in the instruction or NIL."
  (let ((decoder (second instr)))
    (multiple-value-bind (args addr label-type)
	(funcall decoder nib2 nib3 nib4)
      (values (cons (car instr) args)
	      addr
	      label-type))))

(defmacro def-decoder (name &body body)
  "Define a decoder function.  Function name will be \"DECODER-\"
and the NAME argument.  Arguments to the function will be
(NIB2 NIB3 NIB4), the nibbles of the instruction, most significant first"
  `(defun ,(intern (format nil "DECODER-~a" name)) (nib2 nib3 nib4)
     (declare (ignorable nib2 nib3 nib4))
     ,@body))

(def-decoder none
  nil)

(def-decoder reg+byte
  (list (format nil "r~d" nib2) nib3))

(def-decoder reg+regbyte
  (list (format nil "r~d" nib2)
	(format nil "r~d" nib3)))

(defun address-decoder (nib2 nib3 nib4)
  (logior (ash nib4 8) (ash nib3 4) nib2))

(def-decoder paddr
  (let ((addr (address-decoder nib2 nib3 nib4)))
    (values (list addr)
	    addr
	    "code")))

(def-decoder daddr
  (let ((addr (address-decoder nib2 nib3 nib4)))
    (values (list addr)
	    addr
	    "data")))

(def-decoder reg
  (list (format nil "r~d" nib3)))

(def-decoder reg+reg 
  (list (format nil "r~d" nib3)
	(format nil "r~d" nib4)))

