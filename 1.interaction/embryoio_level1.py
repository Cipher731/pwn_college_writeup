from pwn import *

import io


def try1():
    # Succeeded. Control an interactive session.
    # Question: shell=True is not necessary. Why?
    # Answer: shell parameter is irrelevant to tty or something.
    #         It simply indicates that if the binary is executed by shell or not.
    #         See try1_1() for more information
    p = process('/bin/bash', shell=True)
    p.sendline(b'/challenge/embryoio_level1')

    p.recvuntil(b'flag:\n')
    print(p.recvline().decode())


def try1_1():
    # Failed. Because the default shell is dash rather than bash.
    p = process('/challenge/embryoio_level1', shell=True)
    print(p.clean(1))


def try1_2():
    # Failed. It simply acts like try2(). bash -c takes the argument as executable directly.
    p = process('/challenge/embryoio_level1', shell=True, executable='/usr/bin/bash')
    print(p.clean(1))


def try2():
    # Failed. bash -c executes the executable directly without spawning a bash process.
    p = process(['/bin/bash', '-c', '/challenge/embryoio_level1'])
    print(p.clean(1))


def try3():
    # Succeeded. bash -c executes echo immediatly and then pipe the output to a real bash process whom executes the challenge binary.
    p = process(['/bin/bash', '-c', 'echo /challenge/embryoio_level1 | bash'])
    print(p.clean(1))


def try4():
    # Failed. because BytesIO doesn't have real fileno. It is only an IO wrapper for python-level usage
    p = process('/bin/bash', stdin=io.BytesIO(b'/challenge/embryoio_level1\n'))


if __name__ == '__main__':
    try1_2()
