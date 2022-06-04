from pwn import *

p = process('/challenge/embryoio_level15')
print(p.clean(1).decode())
