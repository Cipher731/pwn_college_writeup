from pwn import *
import glob

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''

xor rax, rax

test rdi, rdi  
je end  # if src_addr != 0
    loop:
    cmp byte ptr [rdi], 0
    je end  # while [src_addr] != 0
        cmp byte ptr [rdi], 90
        jg out  # if [src_addr] <= 90
            push rax
            push rdi
            mov dil, byte ptr [rdi]
            mov rax, 0x403000
            call rax
            pop rdi
            mov [rdi], al
            pop rax
            add rax, 1
        out:
        add rdi, 1
    jmp loop

end:
ret
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
p.interactive()
