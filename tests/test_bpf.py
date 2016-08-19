import dpkt
from bpf_asm import BPFAssembler
from bpf_exec import BPFDisassembler
from bpf_exec import BPFTracer

def main():
    # Give the lexer some input
    with open("bpf") as f:
        data = f.read()

    assembler = BPFAssembler()

    program = assembler.assemble(data)

    disassembler = BPFDisassembler()
    disassembler.disassemble(program)

    f = open('gre_and_4over6.cap')
    pcap = dpkt.pcap.Reader(f)

    executor = BPFTracer()
    executor.set_program(program)
    
    for ts, buf in pcap:
       ret = executor.run(buf)

#    
#    for line in program:
#        print '{ 0x%x, %d, %d, 0x%08x },' % line

if __name__ == '__main__':
    main()
