import glob
import time

from pwn import *

bin_path = glob.glob('/challenge/em*')[0]
# p = process([bin_path, *([''] * 31), 'gxftlufdbd'])  # 74
# p = process([], executable=bin_path)  # 75
# p = process([], executable=bin_path, env={'312': 'ufkabtmmat'})  # 76
# p = process([*([''] * 55), 'wurhydmfkx'], executable=bin_path, env={'106': 'wvxihbwmoy'})  # 77
# p = process(f'cd /tmp/yknjxq; exec {bin_path} < xihqma', shell=True)  # 78
p = process(f'mkdir -p /tmp/ikswkq; cd /tmp/ikswkq; exec {bin_path}', shell=True)  # 79


time.sleep(1)
print(p.read(4096).decode())

