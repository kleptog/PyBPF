PyBPF
=====

This module is the result of getting a little frustrated with the available
tools for generating BPF bytecode. There is an assembler/debugger in the
Linux source but they're not very user friendly. This project attempts to be
more generally useful.

bpf_asm
-------

BPF assembler. Accepts BPF source code, outputs in various formats.

bpf_disasm
----------

Read BPF bytecode in various formats and disassembles it.

bpf_dbg
-------

Similar to the bpf_dbg in the Linux source.
