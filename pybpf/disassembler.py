from pybpf.common import BPFConstants

class BPFInvalidOpcode(Exception):
    pass
    
class BPFDecoder(BPFConstants):

    def decode_one(self, op, jt, jf, k):
        class_ =  op & 0x07
        if class_ == self.BPF_LD:
            mode = op & 0xE0
            if mode == self.BPF_IMM:
                return self.op_set_a_imm(k)
            elif mode == self.BPF_MEM:
                return self.op_set_a_mem(k)
            else:
                size = op & 0x18
                if size == self.BPF_W:
                    size = 4
                elif size == self.BPF_H:
                    size = 2
                elif size == self.BPF_B:
                    size = 1
                else:
                    raise BPFInvalidOpcode(op)
                if mode == self.BPF_ABS:
                    return self.op_set_a_abs(k, size)
                elif mode == self.BPF_IND:
                    return self.op_set_a_ind(k, size)
                else:
                    raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_LDX:
            mode = op & (0x18 | 0xE0)
            if mode == self.BPF_W | self.BPF_IMM:
                return self.op_set_x_imm(k)
            elif mode == self.BPF_W | self.BPF_MEM:
                return self.op_set_x_mem(k)
            elif mode == self.BPF_B | self.BPF_MSH:
                return self.op_set_x_msh(k)    
            else:
                raise BPFInvalidOpcode(op)  
        elif class_ == self.BPF_ST:
            return self.op_set_mem_a(k)
        elif class_ == self.BPF_STX:
            return self.op_set_mem_x(k)
        elif class_ == self.BPF_ALU:
            opr = op & (0xF0 | 0x08)
            if opr == self.BPF_ADD | self.BPF_K:
                return self.op_alu_add_k(k)
            elif opr == self.BPF_SUB | self.BPF_K:
                return self.op_alu_sub_k(k)
            elif opr == self.BPF_MUL | self.BPF_K:
                return self.op_alu_mul_k(k)
            elif opr == self.BPF_DIV | self.BPF_K:
                return self.op_alu_div_k(k)
            elif opr == self.BPF_OR | self.BPF_K:
                return self.op_alu_or_k(k)
            elif opr == self.BPF_AND | self.BPF_K:
                return self.op_alu_and_k(k)
            elif opr == self.BPF_LSH | self.BPF_K:
                return self.op_alu_lsh_k(k)
            elif opr == self.BPF_RSH | self.BPF_K:
                return self.op_alu_rsh_k(k)
            elif opr == self.BPF_NEG | self.BPF_K:
                return self.op_alu_neg()
            elif opr == self.BPF_MOD | self.BPF_K:
                return self.op_alu_mod_k(k)
            elif opr == self.BPF_XOR | self.BPF_K:
                return self.op_alu_xor_k(k)
            elif opr == self.BPF_ADD | self.BPF_X:
                return self.op_alu_add_x()
            elif opr == self.BPF_SUB | self.BPF_X:
                return self.op_alu_sub_x()
            elif opr == self.BPF_MUL | self.BPF_X:
                return self.op_alu_mul_x()
            elif opr == self.BPF_DIV | self.BPF_X:
                return self.op_alu_div_x()
            elif opr == self.BPF_OR | self.BPF_X:
                return self.op_alu_or_x()
            elif opr == self.BPF_AND | self.BPF_X:
                return self.op_alu_and_x()
            elif opr == self.BPF_LSH | self.BPF_X:
                return self.op_alu_lsh_x()
            elif opr == self.BPF_RSH | self.BPF_X:
                return self.op_alu_rsh_x()
            elif opr == self.BPF_NEG | self.BPF_X:
                return self.op_alu_neg()
            elif opr == self.BPF_MOD | self.BPF_X:
                return self.op_alu_mod_x()
            elif opr == self.BPF_XOR | self.BPF_X:
                return self.op_alu_xor_x()
        elif class_ == self.BPF_JMP:
            opr = op & (0xF0 | 0x08)
            if opr == self.BPF_JA:
                return self.op_jmp_a(k)
            elif opr == self.BPF_JGT | self.BPF_K:
                return self.op_jmp_gt_k(jt, jf, k)
            elif opr == self.BPF_JGE | self.BPF_K:
                return self.op_jmp_ge_k(jt, jf, k)
            elif opr == self.BPF_JEQ | self.BPF_K:
                return self.op_jmp_eq_k(jt, jf, k)
            elif opr == self.BPF_JSET | self.BPF_K:
                return self.op_jmp_set_k(jt, jf, k)
            elif opr == self.BPF_JGT | self.BPF_X:
                return self.op_jmp_gt_x(jt, jf)
            elif opr == self.BPF_JGE | self.BPF_X:
                return self.op_jmp_ge_x(jt, jf)
            elif opr == self.BPF_JEQ | self.BPF_X:
                return self.op_jmp_eq_x(jt, jf)
            elif opr == self.BPF_JSET | self.BPF_X:
                return self.op_jmp_set_x(jt, jf)
            else:
                raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_RET:
            src = op & 0x18
            if src == self.BPF_K:
                return self.op_ret_k(k)
            elif src == self.BPF_X:
                return self.op_ret_x()
            elif src == self.BPF_A:
                return self.op_ret_a()
            else:
                raise BPFInvalidOpcode(op)
        elif class_ == self.BPF_MISC:
            misc = op & 0xF8
            if misc == self.BPF_TAX:
                return self.op_misc_tax()
            elif misc == self.BPF_TXA:
                return self.op_misc_txa()
            else:
                raise BPFInvalidOpcode(op)
        else:
            raise BPFInvalidOpcode(op)

        
class BPFDisassembler(BPFDecoder):
    def disassemble(self, prog):
        for pc, instr in enumerate(prog):
            s = self.disassemble_one(pc, instr)
            print "l%d:\t%s" % (pc, s)

    def disassemble_one(self, pc, instr):
        (op, jt, jl, k) = instr
        self.pc = pc
        return self.decode_one(op, jt, jl, k)

    def op_set_a_imm(self, k):
        return "ld #0x%x" % k
    
    def op_set_a_mem(self, k):
        return "ld M[%d]" % k
        
    def op_set_a_abs(self, k, size):
        if size == 1:
            return "ldb [%d]" % k
        if size == 2:
            return "ldh [%d]" % k
        if size == 4:
            return "ld [%d]" % k

    def op_set_a_ind(self, k, size):
        if size == 1:
            return "ldb [x+%d]" % k
        if size == 2:
            return "ldh [x+%d]" % k
        if size == 4:
            return "ld [x+%d]" % k

    def op_set_x_imm(self, k):
        return "ldx #0x%x" % k
    
    def op_set_x_mem(self, k):
        return "ldx M[%d]" % k
        
    def op_set_x_msh(self, k):
        return "ldx 4*([%d] & 0xf)" % k
    
    def op_set_mem_a(self, k):
        return "st M[%d]" % k

    def op_set_mem_x(self, k):
        return "stx M[%d]" % k

    def op_alu_add_k(self, k):
        return "add #%d" % k
    def op_alu_sub_k(self, k):
        return "sub #%d" % k
    def op_alu_mul_k(self, k):
        return "mul #%d" % k
    def op_alu_div_k(self, k):
        return "div #%d" % k
    def op_alu_or_k(self, k):
        return "or #0x%x" % k
    def op_alu_and_k(self, k):
        return "and #0x%x" % k
    def op_alu_lsh_k(self, k):
        return "lsh #%d" % k
    def op_alu_rsh_k(self, k):
        return "rsh #%d" % k
    def op_alu_neg():
        return "neg"
    def op_alu_mod_k(self, k):
        return "mod #%d" % k
    def op_alu_xor_k(self, k):
        return "xor #0x%x" % k
        
    def op_alu_add_x(self):
        return "add x"
    def op_alu_sub_x(self):
        return "sub x"
    def op_alu_mul_x(self):
        return "mul x"
    def op_alu_div_x(self):
        return "div x"
    def op_alu_or_x(self):
        return "or x"
    def op_alu_and_x(self):
        return "and x"
    def op_alu_lsh_x(self):
        return "lsh x"
    def op_alu_rsh_x(self):
        return "rsh x"
    def op_alu_mod_x(self):
        return "mod x"
    def op_alu_xor_x(self):
        return "xor x"
        
    def op_ret_k(self, k):
        return "ret #0x%x" % k
    def op_ret_x():
        return "ret x"
    def op_ret_a():
        return "ret a"
        
    def op_misc_tax(self):
        return "tax"
    def op_misc_txa(self):
        return "txa"

    def op_jmp_a(self, k):
        return "jmp l%d" % (self.pc+1+k)
    def op_jmp_gt_k(self, jt, jf, k):
        if jt == 0:
            return "jle #0x%x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jgt #0x%x, l%d" % (k, self.pc+1+jt)
        return "jgt #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_ge_k(self, jt, jf, k):
        if jt == 0:
            return "jlt #0x%x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jge #0x%x, l%d" % (k, self.pc+1+jt)
        return "jge #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_eq_k(self, jt, jf, k):
        if jt == 0:
            return "jneq #0x%x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jeq #0x%x, l%d" % (k, self.pc+1+jt)
        return "jeq #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_set_k(self, jt, jf, k):
        if jf == 0:
            return "jset #0x%x, l%d" % (k, self.pc+1+jt)
        return "jset #0x%x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_gt_x(self, jt, jf):
        if jt == 0:
            return "jle x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jgt x, l%d" % (k, self.pc+1+jt)
        return "jgt x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_ge_x(self, jt, jf):
        if jt == 0:
            return "jlt x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jge x, l%d" % (k, self.pc+1+jt)
        return "jge x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_eq_x(self, jt, jf):
        if jt == 0:
            return "jneq x, l%d" % (k, self.pc+1+jf)
        if jf == 0:
            return "jeq x, l%d" % (k, self.pc+1+jt)
        return "jeq x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)
    def op_jmp_set_x(self, jt, jf):
        if jf == 0:
            return "jset x, l%d" % (k, self.pc+1+jt)
        return "jset x, l%d, l%d" % (k, self.pc+1+jt, self.pc+1+jf)

            
class BPFExecutor(BPFDecoder):
    def set_program(self, prog):
        """ Set program as list of 4-tuples """
        self.prog = prog
        
    def start(self, packet):
        self.a = self.x = 0
        self.m = [0] * 16
        self.pc = 0
        self.retval = None
        self.packet = bytearray(packet)
        
    def step(self):
        if self.retval is not None:
            return False

        op, jt, jf, k = self.prog[self.pc]
        self.pc += 1
        self.decode_one(op, jt, jf, k)
        
        return self.retval is None
        
    def stop(self):
        return self.retval
    
    def run(self, packet):
        self.start(packet)
        while self.step():
            pass
        return self.stop()
        
    def op_set_a_imm(self, k):
        self.a = k
    
    def op_set_a_mem(self, k):
        self.a = self.m[k]
        
    def op_set_a_abs(self, k, size):
        if size == 1:
            self.a = self.packet[k]
        if size == 2:
            self.a = self.packet[k] * 256 + self.packet[k+1]
        if size == 4:
            self.a = ((self.packet[k] * 256 + self.packet[k+1]) * 256 + self.packet[k+2]) * 256 + self.packet[k+3]

    def op_set_a_ind(self, k, size):
        self.op_set_a_abs(self.x + k, size)

    def op_set_x_imm(self, k):
        self.x = k
    
    def op_set_x_mem(self, k):
        self.x = self.m[k]
        
    def op_set_x_msh(self, k):
        self.x = (self.packet[k] & 0x0F) * 4
    
    def op_set_mem_a(self, k):
        self.m[k] = self.a

    def op_set_mem_x(self, k):
        self.m[k] = self.x

    def op_alu_add_k(self, k):
        self.a = (self.a + k) & 0xFFFFFFFF
    def op_alu_sub_k(self, k):
        self.a = (self.a - k) & 0xFFFFFFFF
    def op_alu_mul_k(self, k):
        self.a = (self.a * k) & 0xFFFFFFFF
    def op_alu_div_k(self, k):
        self.a = (self.a // k) & 0xFFFFFFFF
    def op_alu_or_k(self, k):
        self.a |= k
    def op_alu_and_k(self, k):
        self.a &= k
    def op_alu_lsh_k(self, k):
        self.a = (self.a << k) & 0xFFFFFFFF
    def op_alu_rsh_k(self, k):
        self.a >>= k
    def op_alu_neg():
        self.a = -self.a
    def op_alu_mod_k(self, k):
        self.a = (self.a % k) & 0xFFFFFFFF
    def op_alu_xor_k(self, k):
        self.a ^= k
        
    def op_alu_add_x(self):
        self.a = (self.a + self.x) & 0xFFFFFFFF
    def op_alu_sub_x(self):
        self.a = (self.a - self.x) & 0xFFFFFFFF
    def op_alu_mul_x(self):
        self.a = (self.a * self.x) & 0xFFFFFFFF
    def op_alu_div_x(self):
        self.a = (self.a // self.x) & 0xFFFFFFFF
    def op_alu_or_x(self):
        self.a |= self.x
    def op_alu_and_x(self):
        self.a &= self.x
    def op_alu_lsh_x(self):
        self.a = (self.a << self.x) & 0xFFFFFFFF
    def op_alu_rsh_x(self):
        self.a >>= self.x
    def op_alu_mod_x(self):
        self.a = (self.a % self.x) & 0xFFFFFFFF
    def op_alu_xor_x(self):
        self.a ^= self.x
        
    def op_ret_k(self, k):
        self.retval = k
    def op_ret_x():
        self.retval = self.x
    def op_ret_a():
        self.retval = self.a
        
    def op_misc_tax(self):
        self.x = self.a
    def op_misc_txa(self):
        self.a = self.x

    def op_jmp_a(self, k):
        self.pc += k
    def op_jmp_gt_k(self, jt, jf, k):
        self.pc += jt if (self.a > k) else jf
    def op_jmp_ge_k(self, jt, jf, k):
        self.pc += jt if (self.a >= k) else jf
    def op_jmp_eq_k(self, jt, jf, k):
        self.pc += jt if (self.a == k) else jf
    def op_jmp_set_k(self, jt, jf, k):
        self.pc += jt if (self.a & k) else jf
    def op_jmp_gt_x(self, jt, jf):
        self.pc += jt if (self.a > self.x) else jf
    def op_jmp_ge_x(self, jt, jf):
        self.pc += jt if (self.a >= self.x) else jf
    def op_jmp_eq_x(self, jt, jf):
        self.pc += jt if (self.a == self.x) else jf
    def op_jmp_set_x(self, jt, jf):
        self.pc += jt if (self.a & self.x) else jf

class BPFTracer(BPFExecutor):
    def step(self):
        d = BPFDisassembler()
        s = d.disassemble_one(self.pc, self.prog[self.pc])
        
        print "l%d\t%-24s  A=%08X  X=%08X" % (self.pc, s, self.a, self.x)
        return super(BPFTracer, self).step()
       