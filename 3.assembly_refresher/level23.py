import glob

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''
main:
mov rbp, rsp
sub rbp, 2  # Ugly patch. I started accessing bytes from RBP by MISTAKE.
sub rsp, 0x200
    call count_all
    call max
add rbp, 2
mov rsp, rbp
ret

count_all:
    xor rax, rax  # i = 0
    count_loop:  
    cmp rax, rsi 
    jge count_loop_end  # while i < size
        mov bl, byte ptr [rdi + rax]  # bl = [src_addr + i]
        mov rcx, rbp  
        sub rcx, rbx
        sub rcx, rbx  # rcx = rbp - 2 * [src_addr + i]   every byte count takes two bytes to store
        add word ptr [rcx], 1  # inc count on stack
        add rax, 1  # inc i
        jmp count_loop
    count_loop_end:
    ret

max:
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    max_loop:
    cmp rcx, 0xff  
    jg max_loop_end  # while b <= 0xff
        mov rdx, rbp
        sub rdx, rcx
        sub rdx, rcx  # rdx = rbp - 2 * b
        cmp word ptr [rdx], bx
        jle not_larger  # if [rdx] > max_freq
            mov rax, rcx  # max_freq_byte = b
            mov bx, [rdx]  # max_freq = [rdx]
        not_larger:
            add rcx, 1  # inc i
            jmp max_loop
    max_loop_end:
    ret
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
p.interactive()
