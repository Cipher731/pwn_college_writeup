from pwn import *
import os
import time

bin_path = os.listdir('/challenge')[-1]

fd1 = os.pipe()
fd2 = os.pipe()
p0 = process(['rev'], stdout=fd1[1])
p1 = process(['rev'], stdin=fd1[0], stdout=fd2[1])
p2 = process(f'/challenge/{bin_path}', stdin=fd2[0])
time.sleep(1)
p0.sendline(b'uwiechss')
p0.stdin.close()
p2.wait()
print(p2.read(4096).decode())