import subprocess
import glob
import os
import time
import tempfile
import fcntl

bin_path = glob.glob('/challenge/em*')[0]

fd = os.pipe()

os.dup2(fd[0], 315)
p = subprocess.Popen([bin_path], pass_fds=(315,))  # pwntools has no pass_fds param. So, we need to use subprocess

os.write(fd[1], b'hgouolqu')

time.sleep(1)
print(p.read(4096).decode())


