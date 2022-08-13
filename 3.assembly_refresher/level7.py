import glob

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''
mov rax, rdi
shl rax, 24
shr rax, 56
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
print(p.clean().decode())
