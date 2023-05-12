import random
import sys

src_file = open(sys.argv[1], 'r')
data = src_file.readlines()
print(data)
with open('url.txt', 'w') as f:
    for i in range(0, 1000):
        url = random.choice(data)
        f.write(url)