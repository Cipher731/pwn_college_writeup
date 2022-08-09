from pwn import *
import glob
import os
import time


bin_path = glob.glob('/challenge/em*')[0]

p = process(bin_path)

time.sleep(1)
print(p.read(4096).decode())
