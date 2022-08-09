from pwn import *

import glob
import signal
import time
import re

bin_path = glob.glob('/challenge/em*')[0]
p = process(f'echo {bin_path} > /tmp/script.sh; bash /tmp/script.sh', shell=True)

time.sleep(1)

p.readuntil(b'[TEST] You must send me')

output = p.readline().decode()
print(output)

pid = re.search(r'\(PID (\d+)\)', output).group(1)
sigs = re.search(r"in exactly this order: \[(.*)]", output).group(1).replace("'", '').split(', ')

print(pid, sigs)

for sig in sigs:
    sig = getattr(signal, sig)
    os.kill(int(pid), int(sig))
    print(p.read().decode())

p.wait()
print(p.read().decode())
