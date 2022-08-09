from pwn import *

import glob
import signal
import time
import re

p = process(['/home/hacker/challenges/1.interaction/c_wrapper'])

time.sleep(1)

while line := p.readline():
    line = line.decode()
    print(line)

    chal = line.find('for: ')
    if chal > 0:
        p.sendline(str(eval(line[chal+4:].strip())).encode())
