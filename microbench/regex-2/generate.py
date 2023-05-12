import random
import sys
from numpy import loadtxt

data = loadtxt(sys.argv[1])
print(data)
with open('url.txt', 'w') as f:
    for i in range(0, 1000):
        url = random.choice(data)
        f.write(url)
        f.write('\n')