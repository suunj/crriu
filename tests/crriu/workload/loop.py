import time, sys
f = open("f1.txt"); f.read(100)
for i in range(30):
    print(i, f.readline().strip()); sys.stdout.flush(); time.sleep(0.3)
