import random
import sys

src_file = open(sys.argv[1], 'r')
data = src_file.readlines()
data = [x for x in data[:-1]]
print(data)
with open('REGEX.txt', 'w') as f:
    for i in range(0, 1000):
        url = random.choice(data)
        f.write(url)