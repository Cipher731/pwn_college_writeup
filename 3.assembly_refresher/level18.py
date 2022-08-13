import glob

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]

context.arch = 'amd64'
shellcode = asm('''
mov eax, [rdi + 4]
mov ebx, [rdi + 8]
mov ecx, [rdi + 12]
mov edx, [rdi]

cmp edx, 0x7f454c46
je add

cmp edx, 0x00005A4D
je sub

mul:
imul ebx
imul ecx
jmp end

add:
add eax, ebx
add eax, ecx
jmp end

sub:
sub eax, ebx
sub eax, ecx

end:
''')

p = process([bin_path])

print(p.recvuntil(b'Please give me your assembly in bytes (up to 0x1000 bytes):').decode())

p.send(shellcode)
time.sleep(1)
print(p.clean().decode())
