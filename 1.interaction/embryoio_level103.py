from pwn import *
import glob
import os
import time
import fcntl


def method_with_shell_feature():
    bin_path = glob.glob('/challenge/em*')[0]

    p = process(f'cd /tmp/yknjxq; exec {bin_path} < xihqma', shell=True)  

    f = open('/tmp/yknjxq/xihqma', 'w')
    f.write('mybitesk')
    f.close()

    time.sleep(1)
    print(p.read(4096).decode())


def method_with_python():
    def make_and_open_fifo():
        fifo_path = os.path.join(tempfile.mkdtemp(), 'myfifo')
        os.mkfifo(fifo_path, 0o666)

        temp_fd0 = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        temp_fd1 = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)

        return (temp_fd0, temp_fd1)

    bin_path = glob.glob('/challenge/em*')[0]

    # Write ==>[1 fd 0]==> Challenge ==>[1 stdout 0]==> Read
    fd = make_and_open_fifo()

    # Unset NONBLOCK Read
    oldfl = fcntl.fcntl(fd[0], fcntl.F_GETFL)
    fcntl.fcntl(fd[0], fcntl.F_SETFL, oldfl & ~os.O_NONBLOCK)

    p = process([bin_path], stdin=fd[0])

    time.sleep(1)

    os.write(fd[1], b'mybitesk')
    os.close(fd[1])  # Close is a must when using blocking read mode

    time.sleep(1)
    print(p.read(4096).decode())


method_with_python()