import fcntl
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

# Write ==>[1 fd0 0]==> Challenge ==>[1 fd1 0]==> Read
fd0 = make_and_open_fifo()
fd1 = make_and_open_fifo()

# Unset NONBLOCK Read. Otherwise, the checker would read EOF from stdin and mess up
oldfl = fcntl.fcntl(fd0[0], fcntl.F_GETFL)
fcntl.fcntl(fd0[0], fcntl.F_SETFL, oldfl & ~os.O_NONBLOCK)

p = process([bin_path], stdin=fd0[0], stdout=fd1[1])

time.sleep(0.5)
challenge = os.read(fd1[0], 4096).decode()
challenge = challenge.split('solution for: ')[-1].strip()

response = str(eval(challenge))
os.write(fd0[1], response.encode())
os.close(fd0[1])  # Close is a must when using blocking read mode

time.sleep(1)
print(os.read(fd1[0], 4096).decode())
