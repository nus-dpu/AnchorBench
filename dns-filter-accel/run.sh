mkdir result/

for nr_core in $(seq 1 1 7); do 
    echo ">> Test with $nr_core cores >>"
    mkdir result/thp-$nr_core/
    for rate in $(seq 10 20 490); do
        rm thp-*.txt
        sudo build/dns-filter -l 0-${nr_core} -n 4 -a 03:00.0 -a 03:00.1 -- -m "[0-1:-].0,[-:0-1].1" -q 128 -- -l 50 -r /tmp/dns_baseline.rof2.binary -p 03:00.0
        cat thp-*.txt > result/thp-$nr_core/thp-rate-$rate.txt
        echo "  >> Test done!"
        sleep 2
    done
    rm thp-*.txt
done