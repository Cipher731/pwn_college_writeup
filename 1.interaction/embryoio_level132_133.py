import glob
import re
import signal
import time

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]
p = process([bin_path])

time.sleep(1)

p.readuntil(b'You must send me')

output = p.readline().decode()
print(output)

pid = re.search(r'\(PID (\d+)\)', output).group(1)
sigs = re.search(r"in exactly this order: \[(.*)]", output).group(1).replace("'", '').split(', ')

print(pid, sigs)

for sig in sigs:
    time.sleep(0.01)
    sig = getattr(signal, sig)
    os.kill(int(pid), int(sig))
    p.readline()
    p.readline()

p.wait()
print(p.clean().decode())
