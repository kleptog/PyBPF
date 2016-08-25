PyBPF
=====

This module is the result of getting a little frustrated with the available
tools for generating BPF bytecode. There is an assembler/debugger in the
Linux source but they're not very user friendly. This project attempts to be
more generally useful.

In particular it is designed to be able to be incorporated as a library into
other programs that need BPF functionality.  For testing purpose it does
include a single entrypoint, `bpf` which provides access to much of the
basic functionality.

    usage: bpf [-h] {asm,disasm,test,trace} ...

bpf asm
-------

BPF assembler. Accepts BPF source code, outputs in various formats.

    usage: bpf asm [-h] [-c] [input] [output]

    positional arguments:
      input       Input file (default: stdin)
      output      Output file (default: stdin)

    optional arguments:
      -h, --help  show this help message and exit
      -c          output in C style

bpf disasm
----------

Reads BPF bytecode in various formats and disassembles it.

    usage: bpf disasm [-h] [input] [output]

    positional arguments:
      input       Input file (default: stdin)
      output      Output file (default: stdin)

    optional arguments:
      -h, --help  show this help message and exit


bpf_test
--------

Test a given BPF program on a PCAP file. For each packets prints out the
result of the program. Input program can be compiled or uncompiled.

    usage: bpf test [-h] (-f BPF | -p BPF) [pcap]

    positional arguments:
      pcap        Input PCAP file (default: stdin)

    optional arguments:
      -h, --help  show this help message and exit
      -f BPF      BPF Filter (uncompiled)
      -p BPF      BPF Filter (compiled)

bpf trace
---------

Runs the given BPF program over a packet from a PCAP file, showing the
current instruction and registers at each step.

    usage: bpf trace [-h] [-n N] (-f BPF | -p BPF) [pcap]

    positional arguments:
      pcap        Input PCAP file (default: stdin)

    optional arguments:
      -h, --help  show this help message and exit
      -n N        Packet number to trace (1=first)
      -f BPF      BPF Filter (uncompiled)
      -p BPF      BPF Filter (compiled)
