nr_core=$1
start=$2
step=$3
max_rate=$4

mkdir thp-$nr_core/

echo ">> Test with $nr_core cores >>"

for rate in $(seq $start $step $max_rate); do
    echo ">> Rate at $rate... >>"
    mkdir thp-$nr_core/rate-${rate}/
    ./build/dns-filter -l 0-${nr_core} -n 4 -a 03:00.0 -a 03:00.1 -- -m "[1-$nr_core:-].0,[-:1-$nr_core].1" -- -l 50 -r /tmp/dns_baseline.rof2.binary -p 03:00.0
    mv thp-*.txt            thp-$nr_core/rate-${rate}/
    mv network-thp-*.txt    thp-$nr_core/rate-${rate}/
    echo "  >> Test done!"
    sleep 2
done
rm thp-*.txt
