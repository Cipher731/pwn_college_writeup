import glob
import time

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]
p = process(f'echo {bin_path} > /tmp/script.sh; cat - | bash /tmp/script.sh | cat -', shell=True)

time.sleep(1)

p.readuntil(b'need to compute responses for')

while line := p.readline():
    line = line.decode()
    print(line)

    chal = line.find('for: ')
    if chal > 0:
        p.sendline(str(eval(line[chal+4:].strip())).encode())
