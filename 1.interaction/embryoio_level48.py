import os

from pwn import *

r, w = os.pipe()
p1 = process('cat', stdin=r)
p2 = process('/challenge/embryoio_level48', stdout=w)
print(os.read(r, 4096))