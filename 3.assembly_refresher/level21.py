from pwn import *
import glob

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''
xor rax, rax

test rdi, rdi
je end

loop:
    cmp byte ptr [rdi], 0
    je end
    add rdi, 1
    add rax, 1
    jmp loop

end:
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
p.interactive()
