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
    (#xc nope decoder-none)))

(defvar *label-counter* 0)
(defvar *labels* nil)
(define-condition invalid-address () ())

(defun slede8-disassembler (filename &key force-data-ranges)
  (let* ((*label-counter* 0)
	 (s8-data (with-open-file (s filename :element-type 'unsigned-byte)
		    (let ((data (make-array (file-length s) :element-type 'unsigned-byte)))
		      (read-sequence data s)
		      data)))
	 program
	 program-length
	 labels)
    (unless (equalp #(#x2E #x53 #x4C #x45 #x44 #x45 #x38) (subseq s8-data 0 7)) ; ".SLEDE8"
      (error "Not a valid slede8 (.s8) binary file"))
    (setq s8-data (coerce (subseq s8-data 7) 'list))
    (setq program-length (length s8-data))
    (loop with data-array = nil
	  with s8-data = s8-data
	  with address = 0
          for ibyte = (pop s8-data)
	  for nib1 = (and ibyte (logand #x0f ibyte))
	  for nib2 = (and ibyte (ash ibyte -4))
	  for instr = (unless (address-in-ranges address force-data-ranges)
			(let ((i (cdr (assoc nib1 *instructions*))))
                          (when (consp (car i))
			    (setq i (copy-list i))
			    (setf (car i) (cdr (assoc nib2 (car i)))))
			  i))
	  for dbyte = (and instr (pop s8-data))
	  for nib3 = (and dbyte (logand #x0f dbyte))
	  for nib4 = (and dbyte (ash dbyte -4))
	  while ibyte
	  if (or (not instr)  ;; Couldn't decode, so this is a data byte
		 (not dbyte)) 
	    do
	       (push ibyte data-array)
	       (incf address)
          else  ;; We may have an instruction
	  do
	     (handler-case
		 (multiple-value-bind (instruction label)
		     (decode-instruction instr labels program-length nib2 nib3 nib4 dbyte)
		   (when data-array
		     (progn
		       (push (append (list (- address (length data-array))
					   '.data)
				     (nreverse data-array))
			     program)
		       (setq data-array nil)))
		   (push (cons address instruction) program)
		   (incf address 2)
		   (when label
		     (push label labels)))
	       (invalid-address ()
		 ;; Tried to jump out of bounds, so this couldn't have
		 ;; been an instruction after all, must be data
		 (push ibyte data-array)
		 (incf address)
		 (when dbyte ;; put the second byte back.
		   (push dbyte s8-data))))
          end	    
	  finally
	     (when data-array
               (progn
		 (push (append (list (- address (length data-array))
					   '.data)
				     (nreverse data-array))
			     program)
		 (setq data-array nil))))
    (setq *labels* (sort labels #'< :key #'cdr))
    (values (insert-labels (nreverse program)
			   *labels*)
	    program-length)))

(defun insert-labels (program labels)
  (values
   (loop with program = program
	 with labels = labels
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
	   and do (incf address stmt-length))
   labels))

(defun output-slede8 (program &key (stream *standard-output*) (include-address t))
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
  (loop for range in ranges
	do
	   (cond ((and (listp range)
		       (<= (first range) address (second range)))
		  (return range))
		 ((and (numberp range)
		       (<= range address))
		  (return range)))))

(defun decode-instruction (instr labels program-length nib2 nib3 nib4 arg-byte)
  (let ((decoder (second instr)))
    (multiple-value-bind (args label)
	(funcall decoder labels program-length nib2 nib3 nib4 arg-byte)
      (values (cons (car instr) args)
	      label))))

(defun decoder-none (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore labels program-length nib2 nib3 nib4 arg-byte))
  nil)

(defun decoder-reg+byte (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore labels program-length nib3 nib4))
  (list (format nil "r~d" nib2) arg-byte))

(defun decoder-reg+regbyte (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore labels program-length nib4 arg-byte))
  (list (format nil "r~d" nib2)
	(format nil "r~d" nib3)))

(defun decoder-paddr (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore arg-byte))
  (let ((addr (logior (ash nib4 8) (ash nib3 4) nib2)))
    (when (< (1- program-length) addr)
      (signal 'invalid-address))
    (let* ((existing-label (car (rassoc addr labels)))
	   (label (or existing-label
		      (format nil "code~d" (incf *label-counter*)))))
      (values (list label)
	      (unless existing-label
		(cons label addr))))))

(defun decoder-daddr (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore arg-byte))
  (let ((addr (logior (ash nib4 8) (ash nib3 4) nib2)))
    (when (< (1- program-length) addr)
      (signal 'invalid-address))
    (let* ((existing-label (car (rassoc addr labels)))
	   (label (or existing-label
		      (format nil "data~d" (incf *label-counter*)))))
      (values (list label)
	      (unless existing-label
		(cons label addr))))))

(defun decoder-reg (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore labels program-length nib2 nib4 arg-byte))
  (list (format nil "r~d" nib3)))

(defun decoder-reg+reg (labels program-length nib2 nib3 nib4 arg-byte)
  (declare (ignore labels program-length nib2 arg-byte))
  (list (format nil "r~d" nib3)
	(format nil "r~d" nib4)))

