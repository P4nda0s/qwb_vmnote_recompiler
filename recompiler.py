# ===========================
# Author: pandaos
# Time: 2021/7/10 11:21
# ==========================
import struct
from pwn import *

class Decompile:
    def recompile(self, file):
        asm_code = "\n".join(self.asm_code)
        asm_code = asm_code.replace("byte ptr", "")
        asm_code = asm_code.replace("qword ptr", "")
        asm_code = asm_code.replace("QWORD PTR", "")
        code_bin = asm(asm_code, arch="amd64")
        data_bin = self.data.ljust(0x200, b'\x00')
        # 0 ~ 0x200 data
        #  0x200 ~ end code
        open(file, "wb").write(data_bin + code_bin)


    def decrypt_str(self, addr, key):
        addr -= self.data_base
        text = ''
        i = 0
        while self.data[addr + i] != 0:
            text += chr((self.data[addr + i] - i) ^ key)
            i += 1
        print("%x:%s" % (addr, text))
        return text

    def read_memory(self, addr, size):
        addr = addr - self.data_base
        dd = self.data[addr:addr + size]
        print("%x:%s" % (addr, binascii.b2a_hex(dd)))
        return dd

    def fetch(self):
        op = self.code[self.pc]
        self.pc += 1
        return op

    def fetch_word(self):
        data = self.code[self.pc:self.pc + 2]
        data = u16(data)
        self.pc += 2
        return data

    def fetch_dword(self):
        data = self.code[self.pc:self.pc + 4]
        data = u32(data)
        self.pc += 4
        return data

    def fetch_qword(self):
        data = self.code[self.pc:self.pc + 8]
        data = u64(data)
        self.pc += 8
        return data


    def addr_resolve(self, addr):
        return "_" + hex(addr)


    def gen_mul(self, op1, op2):
        code = """
        mov rax, %s
        mov rbx, %s
        mul rbx
        mov %s, rax
        """ % (op1, op2, op1)
        return code


    def disasm_one(self, _pc, next_bb: list):
        addr = self.addr_resolve(self.pc)
        opcode = self.fetch()
        tt = (opcode >> 5) & 0x7
        opcode = opcode & 0x1f
        regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r12', 'r13', 'r10', 'r11', 'rip', 'rbp', 'rsp']
        if opcode == 0:  # push reg
            reg1 = self.fetch()
            self.asm_code.append("%s: push %s" % (addr, regs[reg1]))

        elif opcode == 1:  # mov rx, dd/dw/db:[rx]
            regTarget = self.fetch()
            regSource = self.fetch()
            tts = ["NaN1", "byte ptr", "word ptr", "dword ptr", "qword ptr"]
            self.asm_code.append("%s: mov %s, %s [%s]" % (addr, regs[regTarget], tts[tt], regs[regSource]))

        elif opcode == 2:
            self.asm_code.append("%s: nop" % addr)
        elif opcode == 3:
            reg1 = self.fetch()
            if tt == 0:
                self.asm_code.append("%s: mov %s, [0xbbccdd] #getchar" % (addr, regs[reg1]))
            elif tt == 1:
                self.asm_code.append("%s: mov %s, getint" % (addr, regs[reg1]))
            elif tt == 2:
                self.asm_code.append("%s: mov %s, getLint" % (addr, regs[reg1]))
            else:
                self.asm_code.append("%s: mov [%s], getchar" % (addr, regs[reg1]))
        elif opcode == 4:
            self.asm_code.append("%s: leave" % addr)
        elif opcode == 5:
            reg1 = self.fetch()
            val = 0
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                reg2 = self.fetch()
                self.asm_code.append("%s: sub %s, %s" % (addr, regs[reg1], regs[reg2]))
                return
            self.asm_code.append("%s: sub %s, 0x%x" % (addr, regs[reg1], val))
        elif opcode == 6:
            self.asm_code.append("%s: nop2" % addr)
        elif opcode == 7:
            reg1 = self.fetch()
            val = 0
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                reg2 = self.fetch()
                self.asm_code.append("%s: add %s, %s" % (addr, regs[reg1], regs[reg2]))
                return
            self.asm_code.append("%s: add %s, 0x%x" % (addr, regs[reg1], val))
        elif opcode == 8:
            reg1 = self.fetch()
            val2 = self.fetch_dword()
            tts = ["NaN2", "byte ptr", "word  ptr", "dword  ptr", "qword ptr"]
            self.asm_code.append("%s: mov %s[0x%x], %s " % (addr, tts[tt], val2, regs[reg1]))

        elif opcode == 9:
            reg1 = self.fetch()
            val2 = self.fetch()
            tts = ["NaN3", "byte ptr", "word ptr", "dword ptr", "qword ptr"]
            self.asm_code.append("%s: mov %s[%s], %s " % (addr, tts[tt], regs[val2], regs[reg1]))

        elif opcode == 0xA:
            reg1 = self.fetch()
            valdd = self.fetch_dword()
            tts = ["NaN4", "byte ptr", "word ptr", "dword ptr", "qword ptr"]
            self.asm_code.append("%s: mov %s, %s[0x%x]" % (addr, regs[reg1], tts[tt], valdd))

        elif opcode == 0xB:
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch_qword()
                self.asm_code.append("%s: cmp %s, 0x%x" % (addr, regs[reg1], val))
            else:
                reg2 = self.fetch()
                self.asm_code.append("%s: cmp %s, %s" % (addr, regs[reg1], regs[reg2]))

        elif opcode == 0xC:
            self.asm_code.append("%s: call exit\nmov rdi, rax" % addr)

        elif opcode == 0xD:
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                self.asm_code.append("%s: and %s, %s" % (addr, regs[reg1], regs[self.fetch()]))
                return
            self.asm_code.append("%s: and %s, 0x%x" % (addr, regs[reg1], val))

        elif opcode == 0xE:
            reg1 = self.fetch()
            self.asm_code.append("%s: dec %s" % (addr, regs[reg1]))

        elif opcode == 0xf:  ##
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                self.asm_code.append("%s: div %s, %s" % (addr, regs[reg1], regs[self.fetch()]))
                return
            self.asm_code.append("%s: div %s, 0x%x" % (addr, regs[reg1], val))
        elif opcode == 0x10:
            target = self.fetch()
            jmps = ["jmp", "jz", "jnz", "jl", "jg"]
            sjmp = ""
            if tt > 4:
                sjmp = "jmp"
            else:
                sjmp = jmps[tt]
            self.asm_code.append("%s: %s %s" % (addr, sjmp, self.addr_resolve(target)))
            next_bb.append(target)
            return 1


        elif opcode == 0x11:
            if tt != 0:
                target = self.fetch_dword()
                self.asm_code.append("%s: call %s\nmov rdi, rax" % (addr, self.addr_resolve(target)))
                next_bb.append(target)
            else:
                reg2 = self.fetch()
                self.asm_code.append("%s: call %s\nmov rdi, rax" % (addr, regs[reg2]))

            return

        elif opcode == 0x12:
            reg1 = self.fetch()
            self.asm_code.append("%s: inc %s" % (addr, regs[reg1]))
        elif opcode == 0x13:
            target = self.fetch_dword()
            jmps = ["jmp", "jz", "jnz", "jl", "jg"]
            sjmp = ""
            if tt > 4:
                sjmp = "jmp"
            else:
                sjmp = jmps[tt]
            self.asm_code.append("%s: %s %s" % (addr, sjmp, self.addr_resolve(target)))

        elif opcode == 0x14:
            reg1 = self.fetch()
            self.asm_code.append("%s: pop %s" % (addr, regs[reg1]))
        elif opcode == 0x15:
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                self.asm_code.append("%s: or %s, %s" % (addr, regs[reg1], regs[self.fetch()]))
                return
            self.asm_code.append("%s: or %s, 0x%x" % (addr, regs[reg1], val))
        elif opcode == 0x16:
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                self.asm_code.append("%s: mov %s, %s" % (addr, regs[reg1], regs[self.fetch()]))
                return
            self.asm_code.append("%s: mov %s, 0x%x" % (addr, regs[reg1], val))

        elif opcode == 0x17:
            reg1 = self.fetch()
            if tt == 0:
                self.asm_code.append("%s: mov [r11+0xaa],%s # putchar %s" % (addr, regs[reg1], regs[reg1]))
                return
            elif tt == 1:
                self.asm_code.append("%s: mov [r11+0xaa2], %s # putInt %s" % (addr, regs[reg1], regs[reg1]))
                return
            elif tt == 2:
                self.asm_code.append("%s: putPointer %s" % (addr, regs[reg1]))
                return
            self.asm_code.append("%s: putchar [%s]" % (addr, regs[reg1]))

        elif opcode == 0x18:
            self.asm_code.append("%s: mov rax, rdi\nret" % addr)
            return 1
        elif opcode == 0x19:
            self.asm_code.append("%s: syscall" % addr)
        elif opcode == 0x1a:
            self.asm_code.append("%s: initial" % addr)
        elif opcode == 0x1b:
            reg1 = self.fetch()
            reg2 = self.fetch()
            self.asm_code.append("%s: test %s, %s" % (addr, regs[reg1], regs[reg2]))
        elif opcode == 0x1c:
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                self.asm_code.append("%s: %s" % (addr, self.gen_mul(regs[reg1], regs[self.fetch()])))
                return
            self.asm_code.append("%s: %s" % (addr, self.gen_mul(regs[reg1], val)))
        elif opcode == 0x1d:
            reg1 = self.fetch()
            if tt == 1:
                val = self.fetch()
            elif tt == 2:
                val = self.fetch_word()
            elif tt == 3:
                val = self.fetch_dword()
            elif tt == 4:
                val = self.fetch_qword()
            else:
                self.asm_code.append("%s: xor %s, %s" % (addr, regs[reg1], regs[self.fetch()]))
                return
            self.asm_code.append("%s: xor %s, 0x%x" % (addr,regs[reg1], val))
        else:
            print("Undefined Inst")
            raise


    def __init__(self, file):
        self.asm_code = []
        self.data_bin = open(file, "rb").read()
        self.code_size = u32(self.data_bin[0:4])
        self.data_size = u32(self.data_bin[4:8])
        self.code_base = u32(self.data_bin[8:12])
        self.data_base = u32(self.data_bin[12:16])
        print("code size: %x" % self.code_size)
        print("data size: %x" % self.data_size)
        print("code base: %x" % self.code_base)
        print("data base: %x" % self.data_base)

        self.code = self.data_bin[16:16+self.code_size]
        self.data = self.data_bin[16+self.code_size:16+self.code_size+self.data_size]

        self.pc = 0
        next_bb = []
        while self.pc < len(self.code):
            if self.disasm_one(self.pc, next_bb) == 1:
                self.asm_code.append("  ")

        self.asm_code.append("exit: nop\nret")
        print("\n".join(self.asm_code))


    def disasm_block(self, startAddr):
        next_block = []
        self.pc = startAddr
        while self.pc < len(self.code):
            if self.disasm_one(self.pc, next_block) == 1:
                break
        return next_block




aa = Decompile("note.bin")
aa.recompile("re2.bin")


# str decrypt..
aa.decrypt_str(0x1000, 0x89)
aa.decrypt_str(0x100C, 0x42)
aa.decrypt_str(0x1018, 0x24)
aa.decrypt_str(0x1132, 0x47)
aa.decrypt_str(0x1173, 0x11)
aa.decrypt_str(0x117A, 0x11)
aa.decrypt_str(0x1182, 0x11)
table1 = aa.read_memory(0x101F, 256)
table2 = aa.read_memory(0x1120, 17)
flag1 = ''
for ch in table2:
    idx = table1.find(ch)
    flag1 += chr(idx)
print(flag1)


