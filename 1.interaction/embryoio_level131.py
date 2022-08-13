import glob
import time

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]
p = process([bin_path])

time.sleep(1)

while line := p.readline():
    line = line.decode()
    print(line)

    chal = line.find('for: ')
    if chal > 0:
        p.sendline(str(eval(line[chal+4:].strip())).encode())
