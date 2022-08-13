import glob
import subprocess
import time

bin_path = glob.glob('/challenge/em*')[0]

# subprocess.Popen will automatically set current process's 0,1,2 to child process fd 0,1,2
p = subprocess.Popen([bin_path])

time.sleep(1)
p.wait()
