import glob
import os
import tempfile
import time

from pwn import *

fifo_path = os.path.join(tempfile.mkdtemp(), 'myfifo')
bin_path = glob.glob('/challenge/em*')[0]

os.mkfifo(fifo_path, 0o666)

fd0 = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
fd1 = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)

p = process([bin_path], stdout=fd1)

time.sleep(1)
print(os.read(fd0, 4096).decode())
