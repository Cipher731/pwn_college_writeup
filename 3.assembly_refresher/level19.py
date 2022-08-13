import glob

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]

p = process([bin_path])

print(p.recvuntil(b'Here is an example table:\n').decode())
jump_table_address = p.recvline().decode()[5:5+8]

context.arch = 'amd64'

shellcode = asm(f'''
cmp rdi, 3
jg else
    jmp [rsi + rdi * 8]
else:
    jmp [rsi + 0x20]
''')

p.send(shellcode)
p.interactive()