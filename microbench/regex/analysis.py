import numpy as np
import sys
import os

def print_result(thp, latency):
    print('%8s %8s %8s %8s %8s %8s %8s %8s %8s %8s %8s' % ("Enqueue", "Dequeue", "Average", "Min", "10%", "25%", "Median", "90%", "95%", "99%", "99.9%"))
    print('%8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f' % (thp[:,0], thp[:,1], 
            np.average(latency), np.amin(latency), np.percentile(latency, 10), 
            np.percentile(latency, 25), np.median(dat), np.percentile(dat, 90), 
            np.percentile(dat, 95), np.percentile(dat, 99), np.percentile(dat, 99.9)))

thp = np.loadtxt('thp.txt')
latency = np.loadtxt('latency.txt')

print_result(thp, latency)
