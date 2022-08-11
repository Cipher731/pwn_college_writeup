#!/usr/bin/python -I

import sys
import re
import collections
import string
import random
import textwrap
from collections import defaultdict

import pwnlib
import pwnlib.asm
from unicorn import *
from unicorn.x86_const import *
from capstone import *


pwnlib.context.context.update(arch="amd64")
builtin_print = print
print = lambda text: builtin_print(re.sub("\n{2,}", "\n\n", textwrap.dedent(str(text))))


class EmbryoASMBase:
    """
    EmbryoASM:
    A set of levels to teach people the basics of x86 assembly:
    - registers_use
    - stack
    - functions
    - control statements
    Level Layout:
    === Reg ===
    1. Reg write
    2. Reg modify
    3. Reg complex use
    4. Integer Division
    5. Modulo
    6. Smaller register access
    === Bits in Registers ===
    7. Shifting bits
    8. Logic gates as a mov (bit logic)
    9. Hard bit logic challenge
    === Mem Access ===
    10. Read & Write from static memory location
    11. Sized read & write from static memory
    12. R/W to dynamic memory (stored in registers)
    13. Access adjacent memory given at runtime
    === Stack ===
    14. Pop from stack, modify, push back
    15. Stack operations as a swap
    16. r/w from stack without pop (rsp operations)
    === Control Statements ===
    17. Unconditional jumps (jump trampoline, relative and absolute)
    18. If statement jumps (computing value based on a header in mem)
    19. Switch Statements
    20. For-Loop (summing n numbers in memory)
    21. While-Loop (implementing strlen, stop on null)
    === Functions ===
    22. Making your own function, calling ours
    23. Making your own function with stack vars (the stack frame)
    """

    BASE_ADDR = 0x400000
    CODE_ADDR = BASE_ADDR
    LIB_ADDR = BASE_ADDR + 0x3000
    DATA_ADDR = BASE_ADDR + 0x4000
    BASE_STACK = 0x7FFFFF000000
    RSP_INIT = BASE_STACK + 0x200000
    REG_MAP = {
        "rax": UC_X86_REG_RAX,
        "rbx": UC_X86_REG_RBX,
        "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI,
        "rdi": UC_X86_REG_RDI,
        "rbp": UC_X86_REG_RBP,
        "rsp": UC_X86_REG_RSP,
        "r8": UC_X86_REG_R8,
        "r9": UC_X86_REG_R9,
        "r10": UC_X86_REG_R10,
        "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12,
        "r13": UC_X86_REG_R13,
        "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15,
        "rip": UC_X86_REG_RIP,
        "efl": UC_X86_REG_EFLAGS,
        "cs": UC_X86_REG_CS,
        "ds": UC_X86_REG_DS,
        "es": UC_X86_REG_ES,
        "fs": UC_X86_REG_FS,
        "gs": UC_X86_REG_GS,
        "ss": UC_X86_REG_SS,
    }

    init_memory = {}
    secret_key = random.randint(0, 0xFFFFFFFFFFFFFFFF)

    registers_use = False
    dynamic_values = False
    memory_use = False
    stack_use = False
    bit_logic = False
    ip_control = False
    multi_test = False
    functions = False

    whitelist = None
    blacklist = None

    interrupt_stack_read_length = 4
    interrupt_memory_read_length = 4
    interrupt_memory_read_base = DATA_ADDR

    def __init__(self, asm=None):
        self.asm = asm

        self.emu = None
        self.bb_trace = []

        self.init()

    @property
    def description(self):
        raise NotImplementedError

    @property
    def init_register_values(self):
        return {
            attr: getattr(self, attr)
            for attr in dir(self)
            if attr.startswith("init_") and attr[5:] in self.REG_MAP
        }

    def trace(self):
        raise NotImplementedError

    def init(self, *args, **kwargs):
        pass

    def create(self, *args, **kwargs):
        self.init(*args, **kwargs)

        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.emu.mem_map(self.BASE_ADDR, 2 * 1024 * 1024)
        self.emu.mem_write(self.CODE_ADDR, self.asm)
        self.emu.mem_map(self.BASE_STACK, 2 * 1024 * 1024)
        self.rsp = self.RSP_INIT

        for register, value in self.init_register_values.items():
            setattr(self, register[5:], value)

        for address, value in self.init_memory.items():
            self[address] = value

        self.emu.hook_add(UC_HOOK_BLOCK, self.block_hook, begin=self.CODE_ADDR)
        self.emu.hook_add(
            UC_HOOK_INSN, self.syscall_hook, None, 1, 0, UC_X86_INS_SYSCALL
        )
        self.emu.hook_add(UC_HOOK_CODE, self.code_hook)
        self.emu.hook_add(UC_HOOK_INTR, self.intr_hook)

        if self.whitelist is not None:
            self.emu.hook_add(UC_HOOK_CODE, self.whitelist_hook)
        if self.blacklist is not None:
            self.emu.hook_add(UC_HOOK_CODE, self.blacklist_hook)

    def start(self, begin_until=None):
        if begin_until is None:
            begin_until = (self.CODE_ADDR, self.CODE_ADDR + len(self.asm))
        begin, until = begin_until
        self.emu.emu_start(begin, until)

    def run(self):
        hints = ""

        if self.registers_use:
            hints += """
            In this level you will be working with registers. You will be asked to modify
            or read from registers_use.
            """

        if self.dynamic_values:
            hints += """
            We will now set some values in memory dynamically before each run. On each run
            the values will change. This means you will need to do some type of formulaic
            operation with registers_use. We will tell you which registers_use are set beforehand
            and where you should put the result. In most cases, its rax.
            """

        if self.memory_use:
            hints += """
            In this level you will be working with memory. This will require you to read or write
            to things stored linearly in memory. If you are confused, go look at the linear
            addressing module in 'ike. You may also be asked to dereference things, possibly multiple
            times, to things we dynamically put in memory for you use.
            """

        if self.bit_logic:
            hints += """
            In this level you will be working with bit logic and operations. This will involve heavy use of
            directly interacting with bits stored in a register or memory location. You will also likely
            need to make use of the logic instructions in x86: and, or, not, xor.
            """

        if self.stack_use:
            hints += """
            In this level you will be working with the Stack, the memory region that dynamically expands
            and shrinks. You will be required to read and write to the Stack, which may require you to use
            the pop & push instructions. You may also need to utilize rsp to know where the stack is pointing.
            """

        if self.ip_control:
            hints += """
            In this level you will be working with control flow manipulation. This involves using instructions
            to both indirectly and directly control the special register `rip`, the instruction pointer.
            You will use instructions like: jmp, call, cmp, and the like to implement requests behavior.
            """

        if self.multi_test:
            hints += """
            We will be testing your code multiple times in this level with dynamic values! This means we will
            be running your code in a variety of random ways to verify that the logic is robust enough to
            survive normal use. You can consider this as normal dynamic value se
            """

        if self.functions:
            hints += """
            In this level you will be working with functions! This will involve manipulating both ip control
            as well as doing harder tasks than normal. You may be asked to utilize the stack to save things
            and call other functions that we provide you.
            """

        print(
            f"""
            Welcome to {self.__class__.__name__}
            ==================================================

            To interact with any level you will send raw bytes over stdin to this program.
            To efficiently solve these problems, first run it once to see what you need
            then craft, assemble, and pipe your bytes to this program.

            {hints}
            """
        )

        print(self.description)

        if not self.asm:
            print("Please give me your assembly in bytes (up to 0x1000 bytes): ")
            self.asm = sys.stdin.buffer.read1(0x1000)

        self.create()

        print("Executing your code...")
        print("---------------- CODE ----------------")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(self.asm, self.CODE_ADDR):
            print("0x%x:\t%-6s\t%s" % (i.address, i.mnemonic, i.op_str))
        print("--------------------------------------")

        try:
            won = self.trace()
        except Exception as e:
            print(f"ERROR: {e}")
            won = False

        if won:
            print(open("/flag").read())
        else:
            print("Sorry, no flag :(.")
        return won

    def __getattr__(self, name):
        if name in self.REG_MAP:
            return self.emu.reg_read(self.REG_MAP[name])
        if name in self.init_register_values:
            return self.init_register_values[name]
        raise AttributeError

    def __setattr__(self, name, value):
        if name in self.REG_MAP:
            return self.emu.reg_write(self.REG_MAP[name], value)
        return super().__setattr__(name, value)

    def __getitem__(self, key):
        return self.emu.mem_read(key.start, key.stop - key.start)

    def __setitem__(self, key, value):
        self.emu.mem_write(key, value)

    def dump_state(self, uc):
        print(
            f"+--------------------------------------------------------------------------------+"
        )
        print(f"| {'Registers':78} |")
        print(
            f"+-------+----------------------+-------+----------------------+------------------+"
        )

        lines = []
        lc = False
        line = ""
        for reg, const in self.REG_MAP.items():
            if not lc:
                line = "| "
            # skip flag registers
            if not reg.startswith("r"):
                continue

            line += f" {reg.lower():3}  |  0x{getattr(self, reg):016x}  |"

            if not lc:
                line += " "
                lc = True
            else:
                print(f"{line:80} |")
                line = ""
                lc = False

        if line:
            print(f"{line:38} | {' ':20} | {' ':16} |")

        stack_read_amount = self.interrupt_stack_read_length
        memory_read_amount = self.interrupt_memory_read_length

        memory_read_base = self.interrupt_memory_read_base
        multiple_memory_read = False

        if isinstance(memory_read_base, list):
            multiple_memory_read = True

        read_size = 8
        # stack
        print(
            f"+---------------------------------+-------------------------+--------------------+"
        )
        print(f"| {'Stack location':31} | {'Data (bytes)':23} | {'Data (LE int)':18} |")
        print(
            f"+---------------------------------+-------------------------+--------------------+"
        )
        c = 0
        while True:
            read_addr = self.rsp + c * read_size
            if c > stack_read_amount + 10:
                break
            try:
                if (
                    f"{self[read_addr:read_addr + read_size].hex()[::-1]:0>16}"
                    == "0000000000000000"
                    and c > stack_read_amount
                ):
                    break
                print(
                    f"| 0x{read_addr:016x} (rsp+0x{(c * read_size):04x}) | {self[read_addr:read_addr+1].hex()} {self[read_addr+1:read_addr+2].hex()} {self[read_addr+2:read_addr+3].hex()} {self[read_addr+3:read_addr+4].hex()} {self[read_addr+4:read_addr+5].hex()} {self[read_addr+5:read_addr+6].hex()} {self[read_addr+6:read_addr+7].hex()} {self[read_addr+7:read_addr+8].hex()} | 0x{self[read_addr:read_addr + read_size][::-1].hex():0>16} |"
                )
            except:
                break

            c += 1

        print(
            f"+---------------------------------+-------------------------+--------------------+"
        )
        print(
            f"| {'Memory location':31} | {'Data (bytes)':23} | {'Data (LE int)':18} |"
        )
        print(
            f"+---------------------------------+-------------------------+--------------------+"
        )
        if multiple_memory_read:
            for baseaddr in memory_read_base:
                for i in range(memory_read_amount):
                    read_addr = baseaddr + i * read_size
                    print(
                        f"| {' ':2} 0x{read_addr:016x} (+0x{(i * read_size):04x}) | {self[read_addr:read_addr+1].hex()} {self[read_addr+1:read_addr+2].hex()} {self[read_addr+2:read_addr+3].hex()} {self[read_addr+3:read_addr+4].hex()} {self[read_addr+4:read_addr+5].hex()} {self[read_addr+5:read_addr+6].hex()} {self[read_addr+6:read_addr+7].hex()} {self[read_addr+7:read_addr+8].hex()} | 0x{self[read_addr:read_addr + read_size][::-1].hex():0>16} |"
                    )
                if baseaddr != memory_read_base[-1]:
                    print(
                        "|    -------------------------    |    -----------------    |    ------------    |"
                    )
        else:
            for i in range(memory_read_amount):
                read_addr = memory_read_base + i * read_size
                print(
                    f"| {' ':2} 0x{read_addr:016x} (+0x{(i * read_size):04x}) | {self[read_addr:read_addr+1].hex()} {self[read_addr+1:read_addr+2].hex()} {self[read_addr+2:read_addr+3].hex()} {self[read_addr+3:read_addr+4].hex()} {self[read_addr+4:read_addr+5].hex()} {self[read_addr+5:read_addr+6].hex()} {self[read_addr+6:read_addr+7].hex()} {self[read_addr+7:read_addr+8].hex()} | 0x{self[read_addr:read_addr + read_size][::-1].hex():0>16} |"
                )

        print(
            f"+---------------------------------+-------------------------+--------------------+"
        )

    def block_hook(self, uc, address, size, user_data):
        self.bb_trace.append(address)

    def intr_hook(self, uc, intr_num, user_data):
        if intr_num == 3:
            self.dump_state(uc)

    def syscall_hook(self, uc, user_data):
        if self.rax == 0x3C:
            uc.emu_stop()
        else:
            uc.emu_stop()
            raise Exception(f"syscall {self.rax} not supported")

    def code_hook(self, uc, address, size, user_data):
        pass

    def blacklist_hook(self, uc, address, size, user_data):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        i = next(md.disasm(uc.mem_read(address, size), address))

        if i.mnemonic in self.blacklist:
            uc.emu_stop()
            raise Exception(f"fail: this instruction is not allowed: {i.mnemonic}")

    def whitelist_hook(self, uc, address, size, user_data):
        whitelist = self.whitelist + ["int3"]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        i = next(md.disasm(uc.mem_read(address, size), address))

        if i.mnemonic not in whitelist:
            uc.emu_stop()
            raise Exception(f"fail: this instruction is not allowed: {i.mnemonic}")

    def get_size_of_insn_at(self, idx):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i, insn in enumerate(md.disasm(self.asm, self.CODE_ADDR)):
            if i == idx:
                return insn.size


class EmbryoASMLevel1(EmbryoASMBase):
    """
    Set register
    """

    registers_use = True

    @property
    def description(self):
        return f"""
        In this level you will work with registers_use! Please set the following:
        * rdi = 0x1337
        """

    def trace(self):
        self.start()
        return self.rdi == 0x1337


class EmbryoASMLevel2(EmbryoASMBase):
    """
    Modify register
    """

    init_rdi = random.randint(0, 0x1000)

    registers_use = True
    dynamic_values = True

    @property
    def description(self):
        return f"""
        Many instructions exist in x86 that allow you to do all the normal
        math operations on registers_use and memory. For shorthand, when we say
        A += B, it really means, A = A + B. Here are some useful instructions:
        add reg1, reg2       <=>     reg1 += reg2
        sub reg1, reg2       <=>     reg1 -= reg2
        imul reg1, reg2      <=>     reg1 *= reg2
        div  is a littler harder, we will discuss it later.
        Note: all 'regX' can be replaced by a constant or memory location

        Do the following:
        * add 0x331337 to rdi

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        """

    def trace(self):
        self.start()
        return self.rdi == self.init_rdi + 0x331337


class EmbryoASMLevel3(EmbryoASMBase):
    """
    Reg complex use: calculate y = mx + b
    """

    init_rdi = random.randint(0, 10000)
    init_rsi = random.randint(0, 10000)
    init_rdx = random.randint(0, 10000)

    registers_use = True
    dynamic_values = True

    @property
    def description(self):
        return f"""
        Using your new knowledge, please compute the following:
        f(x) = mx + b, where:
        m = rdi
        x = rsi
        b = rdx
        Place the value into rax given the above.
        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        rdx = {hex(self.init_rdx)}
        """

    def trace(self):
        self.start()
        return self.rax == (self.init_rdi * self.init_rsi) + self.init_rdx


class EmbryoASMLevel4(EmbryoASMBase):
    """
    Integer Division
    """

    init_rdi = random.randint(1000, 10000)
    init_rsi = random.randint(10, 100)

    registers_use = True
    dynamic_values = True

    @property
    def description(self):
        return f"""
        Recall division in x86 is more special than in normal math. Math in here is
        called integer math. This means everything, as it is now, is in the realm
        of whole looking numbers. As an example:
        10 / 3 = 3 in integer math. Why? Because 3.33 gets rounded down to an integer.
        The relevant instructions for this level are:
        mov rax, reg1; div reg2
        Notice: to use this instruction you need to first load rax with the desired register
        you intended to be the divided. Then run div reg2, where reg2 is the divisor. This
        results in:
        rax = rdi / rsi; rdx = remainder
        The quotient is placed in rax, the remainder is placed in rdx.
        Please compute the following:
        speed = distance / time, where:
        distance = rdi
        time = rsi
        Place the value of speed into rax given the above.
        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return self.rax == self.init_rdi // self.init_rsi


class EmbryoASMLevel5(EmbryoASMBase):
    """
    Modulo
    """

    init_rdi = random.randint(1000000, 1000000000)
    init_rsi = 2 ** random.randint(1, 10) - 1

    registers_use = True
    dynamic_values = True

    @property
    def description(self):
        return f"""
        Modulo in assembly is another interesting concept! x86 allows you to get the
        remainder after doing a division on something. For instance:
        10 / 3  ->  remainder = 1
        You can get the remainder of a division using the instructions introduced earlier
        through the div instruction.
        In most programming languages we refer to mod with the symbol '%'.

        Please compute the following:
        rdi % rsi
        Place the value in rax.

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return self.rax == self.init_rdi % self.init_rsi


class EmbryoASMLevel6(EmbryoASMBase):
    """
    Small Register Access
    """

    init_rdi = random.randint(0x0101, 0xFFFF)
    init_rsi = random.randint(0x01000001, 0xFFFFFFFF)

    registers_use = True
    dynamic_values = True
    whitelist = ["mov"]

    @property
    def description(self):
        return f"""
        Another cool concept in x86 is the independent access to lower register bytes.
        Each register in x86 is 64 bits in size, in the previous levels we have accessed
        the full register using rax, rdi or rsi. We can also access the lower bytes of
        each register using different register names. For example the lower
        32 bits of rax can be accessed using eax, lower 16 bits using ax,
        lower 8 bits using al, etc.
        MSB                                    LSB
        +----------------------------------------+
        |                   rax                  |
        +--------------------+-------------------+
                             |        eax        |
                             +---------+---------+
                                       |   ax    |
                                       +----+----+
                                       | ah | al |
                                       +----+----+
        Lower register bytes access is applicable to all registers_use.

        Using only the following instruction(s)
        mov
        Please compute the following:
        rax = rdi modulo 256
        rbx = rsi modulo 65536

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return (self.init_rdi % 256) == self.rax and (self.init_rsi % 65536) == self.rbx


class EmbryoASMLevel7(EmbryoASMBase):
    """
    Shift
    """

    init_rdi = random.randint(0x55AA55AA55AA55AA, 0x99BB99BB99BB99BB)

    dynamic_values = True
    registers_use = True
    bit_logic = True
    whitelist = ["mov", "shr", "shl"]

    @property
    def description(self):
        return f"""
        Shifting in assembly is another interesting concept! x86 allows you to 'shift'
        bits around in a register. Take for instance, rax. For the sake of this example
        say rax only can store 8 bits (it normally stores 64). The value in rax is:
        rax = 10001010
        We if we shift the value once to the left:
        shl rax, 1
        The new value is:
        rax = 00010100
        As you can see, everything shifted to the left and the highest bit fell off and
        a new 0 was added to the right side. You can use this to do special things to
        the bits you care about. It also has the nice side affect of doing quick multiplication,
        division, and possibly modulo.
        Here are the important instructions:
        shl reg1, reg2       <=>     Shift reg1 left by the amount in reg2
        shr reg1, reg2       <=>     Shift reg1 right by the amount in reg2
        Note: all 'regX' can be replaced by a constant or memory location

        Using only the following instructions:
        mov, shr, shl
        Please perform the following:
        Set rax to the 5th least significant byte of rdi
        i.e.
        rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0 |
        Set rax to the value of B4

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        """

    def trace(self):
        self.start()
        return self.rax == (self.init_rdi >> 32) & 0xFF


class EmbryoASMLevel8(EmbryoASMBase):
    """
    Logic gates as a mov (bit logic)
    """

    init_rax = 0xFFFFFFFFFFFFFFFF
    init_rdi = random.randint(0x55AA55AA55AA55AA, 0x99BB99BB99BB99BB)
    init_rsi = random.randint(0x55AA55AA55AA55AA, 0x99BB99BB99BB99BB)

    dynamic_values = True
    registers_use = True
    bit_logic = True
    blacklist = ["mov", "xchg"]

    @property
    def description(self):
        return f"""
        Bitwise logic in assembly is yet another interesting concept!
        x86 allows you to perform logic operation bit by bit on registers.
        For the sake of this example say registers only store 8 bits.
        The values in rax and rbx are:
        rax = 10101010
        rbx = 00110011
        'If we were to perform a bitwise AND of rax and rbx using the and rax, rbx instruction'
        the result would be calculated by ANDing each pair bits 1 by 1 hence why
        it's called a bitwise logic. So from left to right:
        1 AND 0 = 0, 0 AND 0 = 0, 1 AND 1 = 1, 0 AND 1 = 0 ...
        Finally we combine the results together to get:
        rax = 00100010
        Here are some truth tables for reference:
            AND          OR           XOR
         A | B | X    A | B | X    A | B | X
        ---+---+---  ---+---+---  ---+---+---
         0 | 0 | 0    0 | 0 | 0    0 | 0 | 0
         0 | 1 | 0    0 | 1 | 1    0 | 1 | 1
         1 | 0 | 0    1 | 0 | 1    1 | 0 | 1
         1 | 1 | 1    1 | 1 | 1    1 | 1 | 0

        Without using the following instructions:
        mov, xchg
        Please perform the following:
        rax = rdi AND rsi
        i.e. Set rax to the value of (rdi AND rsi)

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return self.rax == self.init_rdi & self.init_rsi


class EmbryoASMLevel9(EmbryoASMBase):
    """
    Hard Bit-Logic Level
    """

    init_rax = 0xFFFFFFFFFFFFFFFF
    init_rdi = random.randint(1000000, 1000000000)

    dynamic_values = True
    registers_use = True
    bit_logic = True
    whitelist = ["and", "xor", "or"]

    @property
    def description(self):
        return f"""
        Using only the following instructions:
        and, or, xor
        Implement the following logic:

        if x is even then
          y = 1
        else
          y = 0
        where:
        x = rdi
        y = rax

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        """

    def trace(self):
        self.start()
        return self.rax == (self.init_rdi & 0x1) ^ 0x1


class EmbryoASMLevel10(EmbryoASMBase):
    """
    Read and Write to memory
    """

    init_value = random.randint(1000000, 2000000)

    dynamic_values = True
    memory_use = True

    @property
    def init_memory(self):
        return {self.DATA_ADDR: self.init_value.to_bytes(8, "little")}

    @property
    def description(self):
        return f"""
        Up until now you have worked with registers as the only way for storing things, essentially
        variables like 'x' in math. Recall that memory can be addressed. Each address contains something
        at that location, like real addresses! As an example: the address '699 S Mill Ave, Tempe, AZ 85281'
        maps to the 'ASU Campus'. We would also say it points to 'ASU Campus'.  We can represent this like:
        ['699 S Mill Ave, Tempe, AZ 85281'] = 'ASU Campus'
        The address is special because it is unique. But that also does not mean other address cant point to
        the same thing (as someone can have multiple houses). Memory is exactly the same! For instance,
        the address in memory that your code is stored (when we take it from you) is {hex(self.BASE_ADDR)}.
        In x86 we can access the thing at a memory location, called dereferencing, like so:
        mov rax, [some_address]        <=>     Moves the thing at 'some_address' into rax
        This also works with things in registers:
        mov rax, [rdi]         <=>     Moves the thing stored at the address of what rdi holds to rax
        This works the same for writing:
        mov [rax], rdi         <=>     Moves rdi to the address of what rax holds.
        So if rax was 0xdeadbeef, then rdi would get stored at the address 0xdeadbeef:
        [0xdeadbeef] = rdi
        Note: memory is linear, and in x86, it goes from 0 - 0xffffffffffffffff (yes, huge).

        Please perform the following:
        1. Place the value stored at 0x404000 into rax
        2. Increment the value stored at the address 0x404000 by 0x1337
        Make sure the value in rax is the original value stored at 0x404000 and make sure
        that [0x404000] now has the incremented value.

        We will now set the following in preparation for your code:
        [0x404000] = {hex(self.init_value)}
        """

    def trace(self):
        self.start()
        return all(
            (
                self[self.DATA_ADDR : self.DATA_ADDR + 8]
                == (self.init_value + 0x1337).to_bytes(8, "little"),
                self.rax == self.init_value,
            )
        )


class EmbryoASMLevel11(EmbryoASMBase):
    """
    Reading specific sizes from addresses
    """

    init_value = random.randint(1000000, 2000000)

    dynamic_values = True
    memory_use = True

    @property
    def init_memory(self):
        return {self.DATA_ADDR: self.init_value.to_bytes(8, "little")}

    @property
    def description(self):
        return f"""
        Recall that registers in x86_64 are 64 bits wide, meaning they can store 64 bits in them.
        Similarly, each memory location is 64 bits wide. We refer to something that is 64 bits
        (8 bytes) as a quad word. Here is the breakdown of the names of memory sizes:
        * Quad Word = 8 Bytes = 64 bits
        * Double Word = 4 bytes = 32 bits
        * Word = 2 bytes = 16 bits
        * Byte = 1 byte = 8 bits
        In x86_64, you can access each of these sizes when dereferencing an address, just like using
        bigger or smaller register accesses:
        mov al, [address]        <=>         moves the least significant byte from address to rax
        mov ax, [address]        <=>         moves the least significant word from address to rax
        mov eax, [address]        <=>         moves the least significant double word from address to rax
        mov rax, [address]        <=>         moves the full quad word from address to rax
        Remember that moving only into al for instance does not fully clear the upper bytes.

        Please perform the following:
        1) Set rax to the byte at 0x404000
        2) Set rbx to the word at 0x404000
        3) Set rcx to the double word at 0x404000
        4) Set rdx to the quad word at 0x404000

        We will now set the following in preparation for your code:
        [0x404000] = {hex(self.init_value)}
        """

    def trace(self):
        self.start()
        return all(
            (
                self.rax
                == int.from_bytes(self[self.DATA_ADDR : self.DATA_ADDR + 1], "little"),
                self.rbx
                == int.from_bytes(self[self.DATA_ADDR : self.DATA_ADDR + 2], "little"),
                self.rcx
                == int.from_bytes(self[self.DATA_ADDR : self.DATA_ADDR + 4], "little"),
                self.rdx
                == int.from_bytes(self[self.DATA_ADDR : self.DATA_ADDR + 8], "little"),
            )
        )


class EmbryoASMLevel12(EmbryoASMBase):
    """
    Write static values to dynamic memory (of different size)
    """

    init_rdi = EmbryoASMBase.DATA_ADDR + (8 * random.randint(0, 250))
    init_rsi = EmbryoASMBase.DATA_ADDR + (8 * random.randint(250, 500))

    target_mem_rdi = 0xDEADBEEF00001337
    target_mem_rsi = 0x000000C0FFEE0000

    interrupt_memory_read_base = [init_rdi, init_rsi]

    dynamic_values = True
    memory_use = True

    @property
    def init_memory(self):
        return {self.init_rdi: b"\xff" * 8, self.init_rsi: b"\xff" * 8}

    @property
    def description(self):
        return f"""
        It is worth noting, as you may have noticed, that values are stored in reverse order of how we
        represent them. As an example, say:
        [0x1330] = 0x00000000deadc0de
        If you examined how it actually looked in memory, you would see:
        [0x1330] = 0xde 0xc0 0xad 0xde 0x00 0x00 0x00 0x00
        This format of storing things in 'reverse' is intentional in x86, and its called Little Endian.

        For this challenge we will give you two addresses created dynamically each run. The first address
        will be placed in rdi. The second will be placed in rsi.
        Using the earlier mentioned info, perform the following:
        1. set [rdi] = {hex(self.target_mem_rdi)}
        2. set [rsi] = {hex(self.target_mem_rsi)}
        Hint: it may require some tricks to assign a big constant to a dereferenced register. Try setting
        a register to the constant than assigning that register to the derefed register.

        We will now set the following in preparation for your code:
        [{hex(self.init_rdi)}] = 0xffffffffffffffff
        [{hex(self.init_rsi)}] = 0xffffffffffffffff
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return all(
            (
                self[self.init_rdi : self.init_rdi + 8]
                == self.target_mem_rdi.to_bytes(8, "little"),
                self[self.init_rsi : self.init_rsi + 8]
                == self.target_mem_rsi.to_bytes(8, "little"),
            )
        )


class EmbryoASMLevel13(EmbryoASMBase):
    """
    Write to dynamic address, consecutive
    """

    init_rdi = EmbryoASMBase.DATA_ADDR + (8 * random.randint(50, 100))
    init_rsi = EmbryoASMBase.DATA_ADDR + (8 * random.randint(200, 250))

    init_mem_rdi = random.randint(1000, 1000000)
    init_mem_rdi_next = random.randint(1000, 1000000)

    interrupt_memory_read_base = [init_rdi, init_rsi]

    dynamic_values = True
    memory_use = True

    @property
    def init_memory(self):
        return {
            self.init_rdi: self.init_mem_rdi.to_bytes(8, "little"),
            self.init_rdi + 8: self.init_mem_rdi_next.to_bytes(8, "little"),
        }

    @property
    def description(self):
        return f"""
        Recall that memory is stored linearly. What does that mean? Say we access the quad word at 0x1337:
        [0x1337] = 0x00000000deadbeef
        The real way memory is layed out is byte by byte, little endian:
        [0x1337] = 0xef
        [0x1337 + 1] = 0xbe
        [0x1337 + 2] = 0xad
        ...
        [0x1337 + 7] = 0x00
        What does this do for us? Well, it means that we can access things next to each other using offsets,
        like what was shown above. Say you want the 5th *byte* from an address, you can access it like:
        mov al, [address+4]
        Remember, offsets start at 0.

        Preform the following:
        1. load two consecutive quad words from the address stored in rdi
        2. calculate the sum of the previous steps quad words.
        3. store the sum at the address in rsi

        We will now set the following in preparation for your code:
        [{hex(self.init_rdi)}] = {hex(self.init_mem_rdi)}
        [{hex(self.init_rdi + 8)}] = {hex(self.init_mem_rdi_next)}
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return self[self.init_rsi : self.init_rsi + 8] == (
            self.init_mem_rdi + self.init_mem_rdi_next
        ).to_bytes(8, "little")


class EmbryoASMLevel14(EmbryoASMBase):
    """
    Pop, Modify, Push
    """

    init_rdi = random.randint(10, 100000)
    init_rsp = EmbryoASMBase.RSP_INIT - 0x8
    init_mem_rsp = random.randint(1000000, 1000000000)

    dynamic_values = True
    stack_use = True

    @property
    def init_memory(self):
        return {self.init_rsp: self.init_mem_rsp.to_bytes(8, "little")}

    @property
    def description(self):
        return f"""
        In these levels we are going to introduce the stack.
        The stack is a region of memory, that can store values for later.
        To store a value a on the stack we use the push instruction, and to retrieve a value we use pop.
        The stack is a last in first out (LIFO) memory structure this means
        the last value pushed in the first value popped.
        Imagine unloading plates from the dishwasher let's say there are 1 red, 1 green, and 1 blue.
        First we place the red one in the cabinet, then the green on top of the red, then the blue.
        Out stack of plates would look like:
        Top ----> Blue
                  Green
        Bottom -> Red
        Now if wanted a plate to make a sandwhich we would retrive the top plate from the stack
        which would be the blue one that was last into the cabinet, ergo the first one out.

        Subtract rdi from the top value on the stack.

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        (stack) [{hex(self.init_rsp)}] = {hex(self.init_mem_rsp)}
        """

    def trace(self):
        self.start()
        return self[self.init_rsp : self.init_rsp + 8] == (
            self.init_mem_rsp - self.init_rdi
        ).to_bytes(8, "little")


class EmbryoASMLevel15(EmbryoASMBase):
    """
    Swap registers_use
    """

    init_rdi = random.randint(1000000, 1000000000)
    init_rsi = random.randint(1000000, 1000000000)

    dynamic_values = True
    stack_use = True
    whitelist = ["push", "pop"]

    @property
    def description(self):
        return f"""
        In this level we are going to explore the last in first out (LIFO) property of the stack.

        Using only following instructions:
        push, pop
        Swap values in rdi and rsi.
        i.e.
        If to start rdi = 2 and rsi = 5
        Then to end rdi = 5 and rsi = 2

        We will now set the following in preparation for your code:
        rdi = {hex(self.init_rdi)}
        rsi = {hex(self.init_rsi)}
        """

    def trace(self):
        self.start()
        return all((self.rsi == self.init_rdi, self.rdi == self.init_rsi))


class EmbryoASMLevel16(EmbryoASMBase):
    """
    R/W from stack without pop
    """

    init_rsp = EmbryoASMBase.RSP_INIT - 0x20
    init_mem_stack = [random.randint(1000000, 1000000000) for _ in range(4)]

    dynamic_values = True
    stack_use = True
    blacklist = ["pop"]

    @property
    def init_memory(self):
        return {
            self.init_rsp + (8 * i): value.to_bytes(8, "little")
            for i, value in enumerate(self.init_mem_stack)
        }

    @property
    def description(self):
        return f"""
        In the previous levels you used push and pop to store and load data from the stack
        however you can also access the stack directly using the stack pointer.
        The stack pointer is stored in the special register rsp.
        rsp always stores the memory address to the top of the stack,
        i.e. the memory address of the last value pushed.
        Similar to the memory levels we can use [rsp] to access the value at the memory address in rsp.

        Without using pop please calculate the average of 4 consecutive quad words stored on the stack.
        Store the average on the top of the stack. Hint:
        RSP+0x?? Quad Word A
        RSP+0x?? Quad Word B
        RSP+0x?? Quad Word C
        RSP      Quad Word D
        RSP-0x?? Average

        We will now set the following in preparation for your code:
        (stack) [{hex(self.RSP_INIT)}:{hex(self.init_rsp)}]
        = {[hex(val) for val in self.init_mem_stack]} (list of things)
        """

    def trace(self):
        self.start()
        return self[self.init_rsp - 8 : self.init_rsp] == (
            sum(self.init_mem_stack) // 4
        ).to_bytes(8, "little")


class EmbryoASMLevel17(EmbryoASMBase):
    """
    Jump to provided code:
    1. relative jump
    2. absoulte jump
    """

    CODE_ADDR = EmbryoASMBase.CODE_ADDR + random.randint(0x10, 0x100)

    init_rsp = EmbryoASMBase.RSP_INIT - 0x8
    init_mem_rsp = random.randint(0x10, 0x100)

    relative_offset = 0x51
    library = pwnlib.asm.asm(
        f"""
        mov rsi, rdi
        mov rdi, {EmbryoASMBase.secret_key}
        mov rax, 0x3c
        syscall
        """
    )

    dynamic_values = True
    ip_control = True

    @property
    def init_memory(self):
        return {
            self.init_rsp: self.init_mem_rsp.to_bytes(8, "little"),
            self.LIB_ADDR: self.library,
        }

    @property
    def description(self):
        return f"""
        Earlier, you learned how to manipulate data in a pseudo-control way, but x86 gives us actual
        instructions to manipulate control flow directly. There are two major ways to manipulate control
        flow: 1. through a jump; 2. through a call. In this level, you will work with jumps. There are
        two types of jumps:
        1. Unconditional jumps
        2. Conditional jumps
        Unconditional jumps always trigger and are not based on the results of earlier instructions.
        As you know, memory locations can store data and instructions. You code will be stored
        at {hex(self.CODE_ADDR)} (this will change each run).
        For all jumps, there are three types:
        1. Relative jumps
        2. Absolute jumps
        3. Indirect jumps
        In this level we will ask you to do both a relative jump and an absolute jump. You will do a relative
        jump first, then an absolute one. You will need to fill space in your code with something to make this
        relative jump possible. We suggest using the `nop` instruction. It's 1 byte and very predictable.
        Useful instructions for this level is:
        jmp (reg1 | addr | offset) ; nop
        Hint: for the relative jump, lookup how to use `labels` in x86.

        Using the above knowledge, perform the following:
        Create a two jump trampoline:
        1. Make the first instruction in your code a jmp
        2. Make that jmp a relative jump to {hex(self.relative_offset)} bytes from its current position
        3. At {hex(self.relative_offset)} write the following code:
        4. Place the top value on the stack into register rdi
        5. jmp to the absolute address {hex(self.LIB_ADDR)}

        We will now set the following in preparation for your code:
        - Loading your given gode at: {hex(self.CODE_ADDR)}
        - (stack) [{hex(self.RSP_INIT - 0x8)}] = {hex(self.init_mem_rsp)}
        """

    def trace(self):
        self.start()
        return all(
            (
                self.rdi == self.secret_key,
                self.rsi == self.init_mem_rsp,
                self.bb_trace
                == [
                    self.CODE_ADDR,
                    self.CODE_ADDR + self.relative_offset + self.get_size_of_insn_at(0),
                    self.LIB_ADDR,
                ],
            )
        )


class EmbryoASMLevel18(EmbryoASMBase):
    """
    If statements
    """

    init_rdi = EmbryoASMBase.DATA_ADDR + random.randint(0x0, 0x100)

    multi_test = True
    ip_control = True

    def init(self):
        self.selector = random.choice(
            [0x7F454C46, 0x00005A4D, random.randint(0, 2 ** 31 - 1)]
        )
        self.init_values = [random.randint(-(2 ** 16), 2 ** 16) for _ in range(3)]
        self.init_memory = {
            self.init_rdi: b"".join(
                value.to_bytes(4, "little", signed=True)
                for value in [self.selector, *self.init_values]
            )
        }

    @property
    def description(self):
        return f"""
        We will now introduce you to conditional jumps--one of the most valuable instructions in x86.
        In higher level programming languages, an if-else structure exists to do things like:
        if x is even:
           is_even = 1
        else:
           is_even = 0
        This should look familiar, since its implementable in only bit-logic. In these structures, we can
        control the programs control flow based on dynamic values provided to the program. Implementing the
        above logic with jmps can be done like so:

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ; assume rdi = x, rax is output
        ; rdx = rdi mod 2
        mov rax, rdi
        mov rsi, 2
        div rsi
        ; remainder is 0 if even
        cmp rdx, 0
        ; jump to not_even code is its not 0
        jne not_even
        ; fall through to even code
        mov rbx, 1
        jmp done
        ; jump to this only when not_even
        not_even:
        mov rbx, 0
        done:
        mov rax, rbx
        ; more instructions here
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        Often though, you want more than just a single 'if-else'. Sometimes you want two if checks, followed
        by an else. To do this, you need to make sure that you have control flow that 'falls-through' to the
        next `if` after it fails. All must jump to the same `done` after execution to avoid the else.
        There are many jump types in x86, it will help to learn how they can be used. Nearly all of them rely
        on something called the ZF, the Zero Flag. The ZF is set to 1 when a cmp is equal. 0 otherwise.

        Using the above knowledge, implement the following:
        if [x] is 0x7f454c46:
           y = [x+4] + [x+8] + [x+12]
        else if [x] is 0x00005A4D:
           y = [x+4] - [x+8] - [x+12]
        else:
           y = [x+4] * [x+8] * [x+12]
        where:
        x = rdi, y = rax. Assume each dereferenced value is a signed dword. This means the values can start as
        a negative value at each memory position.
        A valid solution will use the following at least once:
        jmp (any variant), cmp

        We will now run multiple tests on your code, here is an example run:
        - (data) [{hex(self.DATA_ADDR)}] = {{4 random dwords]}}
        - rdi = {hex(self.DATA_ADDR)}
        """

    def trace(self):
        try:
            for i in range(100):
                self.create()
                self.start()
                if self.selector == 0x7F454C46:
                    correct = (
                        self.init_values[0] + self.init_values[1] + self.init_values[2]
                    ) & 0xFFFFFFFF
                elif self.selector == 0x00005A4D:
                    correct = (
                        self.init_values[0] - self.init_values[1] - self.init_values[2]
                    ) & 0xFFFFFFFF
                else:
                    correct = (
                        self.init_values[0] * self.init_values[1] * self.init_values[2]
                    ) & 0xFFFFFFFF
                assert self.rax == correct
        except AssertionError:
            return False
        return True


class EmbryoASMLevel19(EmbryoASMBase):

    libraries = [
        pwnlib.asm.asm(
            f"""
            mov rsi, rdi
            mov rdi, {EmbryoASMBase.secret_key + i}
            mov rax, 0x3c
            syscall
            """
        )
        for i in range(5)
    ]

    multi_test = True
    ip_control = True

    def init(self):
        self.jump_locations = [
            random.randint(self.LIB_ADDR + (200 * i), self.LIB_ADDR + (200 * i) + 100)
            for i in range(5)
        ]

        self.init_rdi = random.randint(0, 5)
        self.init_rsi = self.DATA_ADDR + random.randint(0, 1024)

        self.init_memory = {
            self.init_rsi: b"".join(
                location.to_bytes(8, "little") for location in self.jump_locations
            ),
            **{
                location: library
                for location, library in zip(self.jump_locations, self.libraries)
            },
        }

        self.instruction_counts = defaultdict(int)

    @property
    def description(self):
        return f"""
        The last set of jump types is the indirect jump, which is often used for switch statements in the
        real world. Switch statements are a special case of if-statements that use only numbers to
        determine where the control flow will go. Here is an example:
        switch(number):
            0: jmp do_thing_0
            1: jmp do_thing_1
            2: jmp do_thing_2
            default: jmp do_default_thing
        The switch in this example is working on `number`, which can either be 0, 1, or 2. In the case that
        `number` is not one of those numbers, default triggers. You can consider this a reduced else-if
        type structure.
        In x86, you are already used to using numbers, so it should be no suprise that you can make if
        statements based on something being an exact number. In addition, if you know the range of the numbers,
        a switch statement works very well. Take for instance the existence of a jump table. A jump table
        is a contiguous section of memory that holds addresses of places to jump. In the above example, the
        jump table could look like:
        [0x1337] = address of do_thing_0
        [0x1337+0x8] = address of do_thing_1
        [0x1337+0x10] = address of do_thing_2
        [0x1337+0x18] = address of do_default_thing
        Using the jump table, we can greatly reduce the amount of cmps we use. Now all we need to check
        is if `number` is greater than 2. If it is, always do:
        jmp [0x1337+0x18]
        Otherwise:
        jmp [jump_table_address + number * 8]
        Using the above knowledge, implement the following logic:
        if rdi is 0:
            jmp {hex(self.jump_locations[0])}
        else if rdi is 1:
            jmp {hex(self.jump_locations[1])}
        else if rdi is 2:
            jmp {hex(self.jump_locations[2])}
        else if rdi is 3:
            jmp {hex(self.jump_locations[3])}
        else:
            jmp {hex(self.jump_locations[4])}
        Please do the above with the following constraints:
        - assume rdi will NOT be negative
        - use no more than 1 cmp instruction
        - use no more than 3 jumps (of any variant)
        - we will provide you with the number to 'switch' on in rdi.
        - we will provide you with a jump table base address in rsi.

        Here is an example table:
            [{hex(self.init_rsi + 0)}] = {hex(self.jump_locations[0])} (addrs will change)
            [{hex(self.init_rsi + 8)}] = {hex(self.jump_locations[1])}
            [{hex(self.init_rsi + 16)}] = {hex(self.jump_locations[2])}
            [{hex(self.init_rsi + 24)}] = {hex(self.jump_locations[3])}
            [{hex(self.init_rsi + 32)}] = {hex(self.jump_locations[4])}
        """

    def code_hook(self, uc, address, size, user_data):
        super().code_hook(uc, address, size, user_data)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        instruction = next(md.disasm(uc.mem_read(address, size), address))
        self.instruction_counts[instruction.mnemonic] += 1

    def trace(self):
        try:
            for _ in range(100):
                self.create()
                self.start()
                jmps = sum(
                    count
                    for instruction, count in self.instruction_counts.items()
                    if instruction.startswith("j")
                )
                cmps = self.instruction_counts["cmp"]
                assert all(
                    (
                        jmps <= 3 and cmps <= 1,
                        self.rdi == min(self.init_rdi, 4) + self.secret_key,
                    )
                )
        except AssertionError:
            return False
        return True


class EmbryoASMLevel20(EmbryoASMBase):
    """
    Compute average of ints array
    """

    init_rdi = EmbryoASMBase.DATA_ADDR + (random.randint(10, 100) * 8)
    init_rsi = random.randint(50, 100)
    init_mem_data = [random.randint(0, 2 ** 32 - 1) for _ in range(init_rsi)]

    interrupt_memory_read_base = init_rdi
    interrupt_memory_read_length = 10

    dynamic_values = True
    ip_control = True

    @property
    def init_memory(self):
        return {
            self.init_rdi + (8 * i): value.to_bytes(8, "little")
            for i, value in enumerate(self.init_mem_data)
        }

    @property
    def description(self):
        return f"""
        In  a previous level you computed the average of 4 integer quad words, which
        was a fixed amount of things to compute, but how do you work with sizes you get when
        the program is running? In most programming languages a structure exists called the
        for-loop, which allows you to do a set of instructions for a bounded amount of times.
        The bounded amount can be either known before or during the programs run, during meaning
        the value is given to you dynamically. As an example, a for-loop can be used to compute
        the sum of the numbers 1 to n:
        sum = 0
        i = 1
        for i <= n:
            sum += i
            i += 1

        Please compute the average of n consecutive quad words, where:
        rdi = memory address of the 1st quad word
        rsi = n (amount to loop for)
        rax = average computed

        We will now set the following in preparation for your code:
        - [{hex(self.init_rdi)}:{hex(self.init_rdi + (self.init_rsi * 8))}] = {{n qwords]}}
        - rdi = {hex(self.init_rdi)}
        - rsi = {self.init_rsi}

        """

    def trace(self):
        self.start()
        return self.rax == sum(self.init_mem_data) // self.init_rsi


class EmbryoASMLevel21(EmbryoASMBase):
    """
    Implement strlen
    """

    multi_test = True
    ip_control = True

    def init(self, *, init_rdi=None, test_string=None):
        if init_rdi is None:
            init_rdi = self.DATA_ADDR + (random.randint(10, 100) * 8)
        if test_string is None:
            test_string = bytes(
                [
                    *random.choices(
                        string.ascii_letters.encode(), k=random.randint(1, 1000)
                    ),
                    0,
                ]
            )

        self.init_rdi = init_rdi
        self.init_memory = {}

        self.test_string = test_string

        if self.init_rdi:
            self.init_memory[self.init_rdi] = self.test_string
            self.interrupt_memory_read_base = self.init_rdi
            self.interrupt_memory_read_length = 10

    @property
    def description(self):
        return f"""
        In previous levels you discovered the for-loop to iterate for a *number* of times, both dynamically and
        statically known, but what happens when you want to iterate until you meet a condition? A second loop
        structure exists called the while-loop to fill this demand. In the while-loop you iterate until a
        condition is met. As an example, say we had a location in memory with adjacent numbers and we wanted
        to get the average of all the numbers until we find one bigger or equal to 0xff:
        average = 0
        i = 0
        while x[i] < 0xff:
            average += x[i]
            i += 1
        average /= i

        Using the above knowledge, please perform the following:
        Count the consecutive non-zero bytes in a contiguous region of memory, where:
        rdi = memory address of the 1st byte
        rax = number of consecutive non-zero bytes
        Additionally, if rdi = 0, then set rax = 0 (we will check)!
        An example test-case, let:
        rdi = 0x1000
        [0x1000] = 0x41
        [0x1001] = 0x42
        [0x1002] = 0x43
        [0x1003] = 0x00
        then: rax = 3 should be set

        We will now run multiple tests on your code, here is an example run:
        - (data) [{hex(self.DATA_ADDR)}] = {{10 random bytes}},
        - rdi = {hex(self.DATA_ADDR)}
        """

    def trace(self):
        try:
            for _ in range(100):
                self.create()
                self.start()
                assert self.rax == len(self.test_string) - 1

            self.create(init_rdi=0)
            self.start()
            assert self.rax == 0

            self.create(test_string=b"\0")
            self.start()
            assert self.rax == 0

        except AssertionError:
            return False
        return True


class EmbryoASMLevel22(EmbryoASMBase):
    """
    strchr as function
    """

    foo = pwnlib.asm.asm(
        f"""
        mov rax, 0x20
        add rax, rdi
        ret
        """
    )
    harness = pwnlib.asm.asm(
        f"""
        mov rax, {EmbryoASMBase.BASE_ADDR}
        call rax
        """
    )

    multi_test = True
    functions = True

    def init(self, *, init_rdi=None, test_string=None):
        if init_rdi is None:
            init_rdi = self.DATA_ADDR + (random.randint(10, 100) * 8)
        if test_string is None:
            test_string = bytes(
                [
                    *random.choices(
                        string.ascii_letters.encode(), k=random.randint(1, 1000)
                    ),
                    0,
                ]
            )

        self.init_rdi = init_rdi
        self.init_memory = {
            self.LIB_ADDR: self.foo,
            self.LIB_ADDR + 0x100: self.harness,
        }

        self.test_string = test_string

        if self.init_rdi:
            self.init_memory[self.init_rdi] = self.test_string
            self.interrupt_memory_read_base = self.init_rdi
            self.interrupt_memory_read_length = 10

    @property
    def description(self):
        return f"""
        In previous levels you implemented a while loop to count the number of
        consecutive non-zero bytes in a contiguous region of memory. In this level
        you will be provided with a contiguous region of memory again and will loop
        over each performing a conditional operation till a zero byte is reached.
        All of which will be contained in a function!

        A function is a callable segment of code that does not destory control flow.
        Functions use the instructions "call" and "ret".

        The "call" instruction pushes the memory address of the next instruction onto
        the stack and then jumps to the value stored in the first argument.

        Let's use the following instructions as an example:
        0x1021 mov rax, 0x400000
        0x1028 call rax
        0x102a mov [rsi], rax

        1. call pushes 0x102a, the address of the next instruction, onto the stack.
        2. call jumps to 0x400000, the value stored in rax.
        The "ret" instruction is the opposite of "call". ret pops the top value off of
        the stack and jumps to it.
        Let's use the following instructions and stack as an example:
                                    Stack ADDR  VALUE
        0x103f mov rax, rdx         RSP + 0x8   0xdeadbeef
        0x1042 ret                  RSP + 0x0   0x0000102a
        ret will jump to 0x102a
        Please implement the following logic:
        str_lower(src_addr):
            rax = 0
            if src_addr != 0:
                while [src_addr] != 0x0:
                    if [src_addr] <= 90:
                        [src_addr] = foo([src_addr])
                        rax += 1
                    src_addr += 1
        foo is provided at {hex(self.LIB_ADDR)}. foo takes a single argument as a value

        We will now run multiple tests on your code, here is an example run:
        - (data) [{hex(self.DATA_ADDR)}] = {{10 random bytes}},
        - rdi = {hex(self.DATA_ADDR)}
        """

    def trace(self):
        begin_until = (self.LIB_ADDR + 0x100, self.LIB_ADDR + 0x100 + len(self.harness))
        try:
            for _ in range(100):
                self.create()
                self.start(begin_until)
                assert all(
                    (
                        self[self.init_rdi : self.init_rdi + len(self.test_string)]
                        == self.test_string.lower(),
                        self.rax == sum(chr(b).isupper() for b in self.test_string),
                    )
                )

            self.create(init_rdi=0)
            self.start(begin_until)
            assert self.rax == 0

            self.create(test_string=b"\0")
            self.start(begin_until)
            assert self.rax == 0

        except AssertionError:
            return False
        return True


class EmbryoASMLevel23(EmbryoASMBase):

    harness = pwnlib.asm.asm(
        f"""
        mov rax, {EmbryoASMBase.BASE_ADDR}
        call rax
        """
    )
     
    multi_test = True
    functions = True

    def init(self):
        test_length = random.randint(10, 40)
        test_min_value = random.randint(1, 0xFE - test_length)
        self.test_list = [
            random.randint(0, test_length // 2) + test_min_value
            for _ in range(test_length)
        ]

        self.init_rdi = self.DATA_ADDR + random.randint(1, 100)
        self.init_rsi = len(self.test_list)
        self.init_memory = {
            self.LIB_ADDR: self.harness,
            self.RSP_INIT - 0x100: b"\0" * 0x100,
            self.init_rdi: bytes(self.test_list),
        }

        self.interrupt_stack_read_length = 20

    @property
    def description(self):
        return f"""
        In the previous level, you learned how to make your first function and how to call other functions. Now
        we will work with functions that have a function stack frame. A function stack frame is a set of
        pointers and values pushed onto the stack to save things for later use and allocate space on the stack
        for function variables.
        First, let's talk about the special register rbp, the Stack Base Pointer. The rbp register is used to tell
        where our stack frame first started. As an example, say we want to construct some list (a contigous space
        of memory) that is only used in our function. The list is 5 elements long, each element is a dword.
        A list of 5 elements would already take 5 registers, so instead, we can make pace on the stack! The
        assembly would look like:
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ; setup the base of the stack as the current top
        mov rbp, rsp
        ; move the stack 0x14 bytes (5 * 4) down
        ; acts as an allocation
        sub rsp, 0x14
        ; assign list[2] = 1337
        mov eax, 1337
        mov [rbp-0x8], eax
        ; do more operations on the list ...
        ; restore the allocated space
        mov rsp, rbp
        ret
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        Notice how rbp is always used to restore the stack to where it originally was. If we don't restore
        the stack after use, we will eventually run out TM. In addition, notice how we subtracted from rsp
        since the stack grows down. To make it have more space, we subtract the space we need. The ret
        and call still works the same. It is assumed that you will never pass a stack address across functions,
        since, as you can see from the above use, the stack can be overwritten by anyone at any time.
        Once, again, please make function(s) that implements the following:
        most_common_byte(src_addr, size):
            b = 0
            i = 0
            for i <= size-1:
                curr_byte = [src_addr + i]
                [stack_base - curr_byte] += 1
            b = 0

            max_freq = 0
            max_freq_byte = 0
            for b <= 0xff:
                if [stack_base - b] > max_freq:
                    max_freq = [stack_base - b]
                    max_freq_byte = b

            return max_freq_byte
        Assumptions:
        - There will never be more than 0xffff of any byte
        - The size will never be longer than 0xffff
        - The list will have at least one element
        Constraints:
        - You must put the "counting list" on the stack
        - You must restore the stack like in a normal function
        - You cannot modify the data at src_addr
        """

    def trace(self):
        try:
            for _ in range(100):
                self.create()
                self.start((self.LIB_ADDR, self.LIB_ADDR + len(self.harness)))
                assert all(
                    (
                        self.rax & 0xFF
                        == collections.Counter(sorted(self.test_list)).most_common(1)[0][0],
                        self.rsp == self.RSP_INIT,
                    )
                )

        except AssertionError:
            return False
        return True


class EmbryoASMLevel24(EmbryoASMBase):

    harness = pwnlib.asm.asm(
        f"""
        mov rax, {EmbryoASMBase.BASE_ADDR}
        call rax
        """
    )

    mangler = pwnlib.asm.asm(
        """
        mov rsi, 0x02fcb89582a24631;
        mov rax, 0x404200;
        mov [rax], rsi;
        add rax, 0x08;
        mov rsi, 0x000081c098443b7f;
        mov [rax], rsi;

        mov rsi, 0x6568745f6b636168;
        mov rax, 0x404100;
        mov [rax], rsi;
        add rax, 0x08;
        mov rsi, 0x0000646c726f775f;
        mov [rax], rsi;
        
        mov rax, 0x404000;
        mov rbx, 0x404200;
        mov rsi, 0;

        loop:
        mov cl, [rax+rsi];
        mov dl, [rbx+rsi];

        test cl, cl;
        je done;
        test dl, dl;
        je done;

        add cl, dl;
        mov [rax+rsi], cl;
        inc rsi;

        jmp loop;

        done:
        mov rsi, 0;
        mov rbx, 0x404100;

        check:
        mov cl, [rax+rsi];
        mov dl, [rbx+rsi];

        cmp cl, dl
        jne fail
        test cl, cl;
        je pass;
        test dl, dl;
        je pass;

        inc rsi;
        jmp check;

        fail:
        mov rax, 0;
        jmp exit;

        pass:
        mov rax, 1;

        exit:
        ret;
        """
    )

    def init(self):
        self.DATA_ADDR
        self.init_memory = {
            self.LIB_ADDR: self.harness,
            self.LIB_ADDR + 0x100: self.mangler,
        }

    @property
    def description(self):
        return f"""
        In the past levels, you were mostly focused on writing assembly. For this level, we'll focus
        on reading it instead! We will be providing you with a snippet of assembly code that will be executed
        after any assembly that you provide. This snippet will be modifying a series of bytes that ends in
        a null byte (hint: a string!) with the intention of garbling your input. Then, that series of bytes
        will be checked against an expected result. Finally, if the input you provide results in this check
        being passed, you'll get the flag!

        Here's the snippet of code in question:
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        mov rsi, 0x02fcb89582a24631;
        mov rax, 0x404200;
        mov [rax], rsi;
        add rax, 0x08;
        mov rsi, 0x000081c098443b7f;
        mov [rax], rsi;

        mov rsi, 0x6568745f6b636168;
        mov rax, 0x404100;
        mov [rax], rsi;
        add rax, 0x08;
        mov rsi, 0x0000646c726f775f;
        mov [rax], rsi;
        
        mov rax, 0x404000;
        mov rbx, 0x404200;
        mov rsi, 0;

        loop:
        mov cl, [rax+rsi];
        mov dl, [rbx+rsi];

        test cl, cl;
        je done;
        test dl, dl;
        je done;

        add cl, dl;
        mov [rax+rsi], cl;
        inc rsi;

        jmp loop;

        done:
        mov rsi, 0;
        mov rbx, 0x404100;

        check:
        mov cl, [rax+rsi];
        mov dl, [rbx+rsi];

        cmp cl, dl
        jne fail
        test cl, cl;
        je pass;
        test dl, dl;
        je pass;

        inc rsi;
        jmp check;

        fail:
        mov rax, 0;
        jmp exit;

        pass:
        mov rax, 1;

        exit:
        ret;
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        The goal of this challenge is simple: write assembly that populates the buffer at {self.DATA_ADDR:#08x}
        with the correct data that causes the above snippet to return with rax == 1. Note that this challenge
        will append the above assembly to your input, so it will execute directly after. Finally, your
        input is treated as part of a function (your code will be called), so make sure you restore the
        stack if you end up using it at all.

        Assumptions:
        - The bytes for your input will start at: {self.DATA_ADDR:#08x}.
        - The bytes for your input end with a null byte (0x00).
        - Your input will be a valid ASCII string after it has been mangled.
        
        Constraints:
        - You must load the correct input data at: {self.DATA_ADDR:#08x}.
        - The above assembly code will be compiled and appended to your input.
        """

    def create(self, *args, **kwargs):
        self.asm += self.mangler
        super().create(*args, **kwargs)

    def trace(self):
        self.create()
        self.start((self.LIB_ADDR, self.LIB_ADDR + len(self.harness)))
        return self.rax == 1


def main():
    assert len(sys.argv) == 2
    choice = sys.argv[1]

    try:
        choice = int(choice)
    except ValueError:
        print(f"Invalid level choice: {choice}")
        return

    level = globals().get(f"EmbryoASMLevel{choice}")
    if not level:
        print(f"Invalid level choice: {choice}")
        return

    try:
        level().run()
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
