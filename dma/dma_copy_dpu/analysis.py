import numpy as np

dat = np.loadtxt('latency.txt')
dat = dat[:,2]
print('%6s %8s %8s %8s %8s %8s %8s %8s' % ("", "Average", "Min", "10%", "25%", "Median", "90%", "99%"))
print('%6s %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f' % ("Lat(ns)", np.average(dat), np.amin(dat), np.percentile(dat, 10), np.percentile(dat, 25), np.median(dat), np.percentile(dat, 90), np.percentile(dat, 99)))

thp = np.loadtxt('thp.txt')
print('RX: %8.5f (MRPS), SHORT: %8.5f (MRPS), LONG: %8.5f (MRPS), TX %8.5f (MRPS)' % (np.sum(thp[:,0]), np.sum(thp[:,1]), np.sum(thp[:,2]), np.sum(thp[:,3])))
print('%.5f %.5f %.5f' % (np.sum(thp[:,0]), np.sum(thp[:,1]), np.sum(thp[:,2])))
