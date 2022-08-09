from pwn import *

import glob
import signal
import time
import re

bin_path = glob.glob('/challenge/em*')[0]
p = process([bin_path])

time.sleep(1)

output = p.read().decode()
print(output)

pid = re.search(r'\(PID (\d+)\)', output).group(1)
sigs = re.search(r"in exactly this order: \[(.*)]", output).group(1).replace("'", '').split(', ')

print(pid, sigs)

for sig in sigs:
    time.sleep(0.5)
    sig = getattr(signal, sig)
    os.kill(int(pid), int(sig))

p.wait()
print(p.read().decode())
