from pwn import *
import glob

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''
mov rax, [rdi]
mov rbx, [rdi + 8]
add rax, rbx
mov qword ptr [rsi], rax
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
print(p.clean().decode())
