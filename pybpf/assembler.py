from pybpf.common import BPFConstants

import ply.lex as lex
import ply.yacc as yacc

class BPFLexer(object):
    words = ("ldb", "ldh", "ld", "ldi", "ldx", "ldxi", "ldxb", "st", "stx", "jmp", "ja",
             "jeq", "jneq", "jne", "jlt", "jle", "jgt", "jge", "jset", "add", "sub",
             "mul", "div", "mod", "neg", "and", "xor", "or", "lsh", "rsh", "ret", "tax",
             "txa", "x", "a", "m")

    def t_ID(self, t):
        r'[a-zA-Z]\w*'
        if t.value.lower() in self.words:
            t.type = t.value = t.value.upper()
        return t

    literals = ":,#%[]()+*&"

    def t_NUMBER(self, t):
        r'(?i)[-+]?(0x[0-9a-f]+|0b[01]+|[1-9]\d*|0\d*)'
        t.value = int(t.value, 0)
        return t

    def t_COMMENT(self, t):
        r'/\*.*?\*/|;.*|^\#.*'

    def t_WHITE(self, t):
        r'\s+'

    tokens = (
        "NUMBER", "COMMENT", "WHITE", "ID",
    ) + tuple(w.upper() for w in words)

    # Build the lexer
    def build(self, **kwargs):
        self.lexer = lex.lex(module=self, **kwargs)

    def t_error(self, t):
        print("Illegal character '%s'" % t.value[0])
        t.lexer.skip(1)

    def input(self, data):
        self.lexer.input(data)

    def token(self):
        return self.lexer.token()

class BPFParser(BPFConstants):
    def p_program_line(self, p):
        """ program : line """
        p[0] = [p[1]]

    def p_program(self, p):
        """ program : program line """
        p[0] = p[1] + [p[2]]

    def p_recover(self, p):
        """ line : error """
        import pdb; pdb.set_trace()

    def p_line(self, p):
        """ line : label instr """
        p[0] = (p[1], p[2])

    def p_label(self, p):
        """ label : ID ':' """
        p[0] = p[1]

    def p_no_label(self, p):
        """ label : """
        p[0] = None

    def p_instr_alu_neq(self, p):
        """ instr : NEG """
        p[0] = (self.BPF_ALU | self.BPF_NEG, 0, 0, 0)

    def p_instr_alu_x(self, p):
        """ instr : instr_alu_name reg_x """
        p[0] = (p[1] | self.BPF_X, 0, 0, 0)

    def p_instr_alu_k(self, p):
        """ instr : instr_alu_name '#' NUMBER """
        p[0] = (p[1] | self.BPF_K, 0, 0, p[3])

    def p_instr_alu_name(self, p):
        """ instr_alu_name : ADD 
                           | SUB 
                           | MUL 
                           | DIV 
                           | AND 
                           | OR 
                           | LSH 
                           | RSH 
                           | MOD
                           | XOR """
        p[0] = self.BPF_ALU | getattr(self, 'BPF_' + p[1])

    def p_instr_jmp_always(self, p):
        """ instr : JMP ID 
                  | JA ID """
        p[0] = (self.BPF_JMP | self.BPF_JA, 0, 0, p[2])

    def p_instr_jmp_if(self, p):
        """ instr : instr_jmp_name '#' NUMBER ',' ID """
        instr, inverted = p[1]
        p[0] = (instr, 
                p[5] if not inverted else 0, 
                p[5] if inverted else 0, 
                p[3])

    def p_instr_jmp_if_else(self, p):
        """ instr : instr_jmp_name '#' NUMBER ',' ID ',' ID """
        instr, inverted = p[1]
        p[0] = (instr,
                p[5] if not inverted else p[7],
                p[5] if inverted else p[7], 
                p[3])

    def p_instr_jmp_name_true(self, p):
        """ instr_jmp_name : JEQ 
                           | JGE 
                           | JGT 
                           | JSET """
        p[0] = (self.BPF_JMP | getattr(self, 'BPF_' + p[1].upper()), False)

    def p_instr_jmp_name_false(self, p):
        """ instr_jmp_name : JNEQ 
                           | JNE
                           | JLE 
                           | JLT """
        if p[1] == 'JNEQ' or p[1] == 'JNE':
            p[0] = (self.BPF_JMP | self.BPF_JEQ, True)
        if p[1] == 'JLE':
            p[0] = (self.BPF_JMP | self.BPF_JGT, True)
        if p[1] == 'JLT':
            p[0] = (self.BPF_JMP | self.BPF_JGE, True)

    def p_instr_misc_tax(self, p):
        """ instr : TAX """
        p[0] = (self.BPF_MISC | self.BPF_TAX, 0, 0, 0)

    def p_instr_misc_txa(self, p):
        """ instr : TXA """
        p[0] = (self.BPF_MISC | self.BPF_TXA, 0, 0, 0)

    def p_instr_misc_ret_const(self, p):
        """ instr : RET '#' NUMBER """
        p[0] = (self.BPF_RET | self.BPF_K, 0, 0, p[3])

    def p_instr_misc_ret_a(self, p):
        """ instr : RET '%' A 
                  | RET A """
        p[0] = (self.BPF_RET | self.BPF_A, 0, 0, 0)

    def p_instr_ld_imm(self, p):
        """ instr : LD '#' NUMBER 
                  | LDI '#' NUMBER """
        p[0] = (self.BPF_LD | self.BPF_IMM, 0, 0, p[3])

    def p_instr_ld_mem(self, p):
        """ instr : LD M '[' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_MEM, 0, 0, p[3])

    def p_instr_ld_abs_w(self, p):
        """ instr : LD '[' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_W | self.BPF_ABS, 0, 0, p[3])

    def p_instr_ld_abs_h(self, p):
        """ instr : LDH '[' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_H | self.BPF_ABS, 0, 0, p[3])

    def p_instr_ld_abs_b(self, p):
        """ instr : LDB '[' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_B | self.BPF_ABS, 0, 0, p[3])

    def p_instr_ld_ind_w(self, p):
        """ instr : LD '[' reg_x '+' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_W | self.BPF_IND, 0, 0, p[5])

    def p_instr_ld_ind_h(self, p):
        """ instr : LDH '[' reg_x '+' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_H | self.BPF_IND, 0, 0, p[5])

    def p_instr_ld_ind_b(self, p):
        """ instr : LDB '[' reg_x '+' NUMBER ']' """
        p[0] = (self.BPF_LD | self.BPF_B | self.BPF_IND, 0, 0, p[5])

    def p_instr_ldx_imm(self, p):
        """ instr : LDX '#' NUMBER 
                  | LDXI '#' NUMBER """
        p[0] = (self.BPF_LDX | self.BPF_W | self.BPF_IMM, 0, 0, p[3])

    def p_instr_ldx_mem(self, p):
        """ instr : LDX M '[' NUMBER ']' """
        p[0] = (self.BPF_LDX | self.BPF_W | self.BPF_MEM, 0, 0, p[3])

    def p_instr_ldx_special(self, p):
        """ instr : LDX NUMBER '*' '(' '[' NUMBER ']' '&' NUMBER ')' 
                  | LDXB NUMBER '*' '(' '[' NUMBER ']' '&' NUMBER ')' """
        if p[1] != 4 or p[8] != 0xF:
            raise yacc.SyntaxError()
        p[0] = (self.BPF_LDX | self.BPF_B | self.BPF_MSH, 0, 0, p[6])

    def p_instr_st(self, p):
        """ instr : ST M '[' NUMBER ']' """
        p[0] = (self.ST, 0, 0, p[3])

    def p_instr_stx(self, p):
        """ instr : STX M '[' NUMBER ']' """
        p[0] = (self.STX, 0, 0, p[3])

    def p_x(self, p):
        """ reg_x : '%' X 
                  | X """

    def p_error(self, p):
        print "Syntax error"

    def build(self, lexer):
        self.lexer = lexer
        self.tokens = lexer.tokens
        self.parser = yacc.yacc(module=self)

    def parse(self, data, debug=False):
        return self.parser.parse(data, lexer=self.lexer, debug=debug)


class BPFAssembler(object):
    def __init__(self):
        self.lexer = BPFLexer()
        self.lexer.build()
        self.parser = BPFParser()
        self.parser.build(lexer=self.lexer)

    def assemble(self, data):
        raw = self.parser.parse(data)

        labels = dict()
        for i, (label, _) in enumerate(raw):
            if label is None:
                continue
            if label in labels:
                raise SyntaxError("Duplicate label %r" % label)
            labels[label] = i

        def fix_label(f):
            if isinstance(instr[f], str):
                if instr[f] not in labels:
                    raise SyntaxError("Unknown label %r" % label)
                instr[f] = labels[instr[f]] - i - 1

        instrs = []
        for i, (_, instr) in enumerate(raw):
            instr = list(instr)
            fix_label(1)
            fix_label(2)
            fix_label(3)
            instr[1] &= 0xFF;
            instr[2] &= 0xFF;
            instr[3] &= 0xFFFFFFFF;
            instrs.append(tuple(instr))

        return instrs

