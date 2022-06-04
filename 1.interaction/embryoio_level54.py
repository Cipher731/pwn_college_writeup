from pwn import *
import os
import glob

bin_path = glob.glob('/challenge/em*')[0]

# fd1 = os.pipe()
fd2 = os.pipe()
# p0 = process(['rev'], stdout=fd1[1])
p1 = process(['rev'], stdout=fd2[1])
# p1 = process(['cat'], stdin=fd2[0])
# p1 = process(['grep', ''], stdin=fd2[0])
# p1 = process(['sed', ''], stdin=fd2[0])
# p1 = process(['rev'], stdin=fd2[0])
# p2 = process(bin_path, stdout=fd2[1])
p2 = process(bin_path, stdin=fd2[0])
time.sleep(1)
p1.sendline(b'scitmfak'[::-1])
p1.stdin.close()
p2.wait()
print(p2.read(4096).decode())