import sys
import argparse

import dpkt
from pybpf.assembler import BPFAssembler
from pybpf.reader import BPFReader
from pybpf.disassembler import BPFDisassembler
from pybpf.disassembler import BPFTracer

def assembler_main(args):
    data = args.input.read()

    assembler = BPFAssembler()

    program = assembler.assemble(data)
    if not program:
        sys.stderr.write("Assembler failed\n")
        return 1

    if args.c:    
        for line in program:
            args.output.write('{ 0x%x, %d, %d, 0x%08x },\n' % line)
    else:
        args.output.write("%d," % len(program))
        for line in program:
            args.output.write("%u %u %u %u," % line)
        args.output.write("\n")
    return 0

def disassembler_main(args):

    program = BPFReader().read(args.input)
    disassembler = BPFDisassembler()
    code = disassembler.disassemble(program)

    return 0
    f = open('gre_and_4over6.cap')
    pcap = dpkt.pcap.Reader(f)

    executor = BPFTracer()
    executor.set_program(program)
    
    for ts, buf in pcap:
       ret = executor.run(buf)

#    

def main():

    parser = argparse.ArgumentParser(description='BPF tool')
    
    subparsers = parser.add_subparsers()
    
    subparser = subparsers.add_parser('asm')
    subparser.add_argument('input', help="Input file (default: stdin)",
                        nargs='?', type=argparse.FileType('r'), default='-')
    subparser.add_argument('output', help="Output file (default: stdin)",
                        nargs='?', type=argparse.FileType('w'), default='-')
    subparser.add_argument('-c', action='store_true', help="output in C style")
    subparser.set_defaults(func=assembler_main)

    subparser = subparsers.add_parser('disasm')
    subparser.add_argument('input', help="Input file (default: stdin)",
                        nargs='?', type=argparse.FileType('r'), default='-')
    subparser.add_argument('output', help="Output file (default: stdin)",
                        nargs='?', type=argparse.FileType('w'), default='-')
    subparser.set_defaults(func=disassembler_main)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
