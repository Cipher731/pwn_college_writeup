import glob
import os
import time

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]

pp_0 = os.pipe()
p_0 = process(['cat'], stdout=pp_0[1])
pp_1 = os.pipe()
p_1 = process([bin_path], stdin=pp_0[0], stdout=pp_1[1])
p_2 = process(['cat'], stdin=pp_1[0])

time.sleep(1)

while line := p_2.readline():
    line = line.decode()
    print(line)

    chal = line.find('for: ')
    if chal > 0:
        p_0.sendline(str(eval(line[chal+4:].strip())).encode())

p_2.wait()
print(p_2.clean().decode())
