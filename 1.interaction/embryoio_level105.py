import glob
import os
import tempfile
import time

from pwn import *


def make_and_open_fifo():
    fifo_path = os.path.join(tempfile.mkdtemp(), 'myfifo')
    os.mkfifo(fifo_path, 0o666)

    temp_fd0 = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
    temp_fd1 = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)

    return (temp_fd0, temp_fd1)


bin_path = glob.glob('/challenge/em*')[0]

fd0 = make_and_open_fifo()
fd1 = make_and_open_fifo()

p = process([bin_path], stdin=fd0[0], stdout=fd1[1])

os.write(fd0[1], b'enelhluz')
os.close(fd0[1])  # Not necessary for finishing challenge

time.sleep(1)
print(os.read(fd1[0], 4096).decode())

