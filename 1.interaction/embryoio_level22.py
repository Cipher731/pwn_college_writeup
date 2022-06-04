from pwn import *


p = process(['/challenge/embryoio_level29'], env={})
p.interactive()