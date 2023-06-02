nr_core=$1
start=$2
step=$3
max_rate=$4

mkdir lat-$nr_core/
mkdir thp-$nr_core/

echo ">> Test with $nr_core cores >>"

for rate in $(seq $start $step $max_rate); do
    echo ">> Rate at $rate... >>"
    rm lat-*.txt thp-*.txt
    ./build/dns-filter -l 0-${nr_core} -n 4 -a 03:00.0 -a 03:00.1 -- -m "[1-$nr_core:-].0,[-:1-$nr_core].1" -q 128 -- -l 50 -r /tmp/dns_baseline.rof2.binary -p 03:00.0
    cat lat-*.txt > lat-$nr_core/lat-rate-$rate.txt
    cat thp-*.txt > thp-$nr_core/thp-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done
rm lat-*.txt thp-*.txt
