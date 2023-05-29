nr_cores=1
step=20
max_rate=600

mkdir thp-$nr_cores/

echo ">> Test with $nr_core cores >>"
mkdir result/thp-$nr_core/
for rate in $(seq 10 $step $max_rate); do
    rm thp-*.txt
    .build/dns-filter -l 0-${nr_core} -n 4 -a 03:00.0 -a 03:00.1 -- -m "[1-$nr_cores:-].0,[-:1-$nr_cores].1" -q 128 -- -l 50 -r /tmp/dns_baseline.rof2.binary -p 03:00.0
    cat thp-*.txt > thp-$nr_core/thp-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done
rm thp-*.txt
