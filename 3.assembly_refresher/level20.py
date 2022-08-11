from pwn import *
import glob

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''
loop:
    cmp rbx, rsi
    jge end
    add rax, [rdi + rbx * 8]
    add rbx, 1
    jmp loop
end:
    div rsi
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
p.interactive()
