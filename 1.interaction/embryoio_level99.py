from pwn import *
import glob
import os
import time


bin_path = glob.glob('/challenge/em*')[0]

p = process(bin_path)

p.readuntil('solution for: ')
q = p.readline()
result = str(eval(q.decode().strip()))
p.sendline(result.encode())  # eval is evil

p.readuntil('Here is your flag:\n')
print(p.read())
