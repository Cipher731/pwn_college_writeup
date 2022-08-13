import glob
import time


bin_path = glob.glob('/challenge/em*')[0]

# p = process(argv='/tmp/ynqbcj', executable=bin_path)  # 101
# p = process(argv='zesszt', executable=bin_path)  # 102

time.sleep(1)
print(p.read(4096).decode())
