# Slede8 disassembler

## What is this?

Slede8 is a toy 8-bit computer architecture used in a Norwegian CTF
advent calendar.  See https://github.com/PSTNorge/slede8 and
https://slede8.npst.no/

The emulator at https://slede8.npst.no/ can assemble code to binary
files, but it can't load the binaries.  Some tasks in the advent
calendar supplied a binary file, and it would be useful to see the
original program.  So I made this.

## How to use

1. Load the .lisp file in a Common Lisp environment (tested in
   Lispworks, should work in any CL implementation), optionally
   compiling it first.
2. Save your .s8 file somewhere accessible.
3. Call (slede8-disassembler:slede8-disassembler "/path/to/file.s8")
4. Pay attention to any warnings emitted.  They are indications of
   parse errors, often because data bytes have been interpreted as
   instructions.
5. The disassembler will separate jump target addresses from
   load/store addresses.  The former will be labeled "codeN", while
   the latter will be labeled "dataN" (names based on first
   instruction referencing the address).  Pay attention to dataN-labels
   preceeding instructions, and codeN labels preceeding .DATA
   statements.
6. Use intuition and the clues provided by steps 4 and 5 to guide the
   :force-data-ranges parameter.  Go to step 3 and adjust the call.
7. When you're happy, call the disassembler again, this time adding
   :include-address-in-output nil to the parameters.  The result
   should be copy/pasteable to https://slede8.npst.no/


