# queue_depth=(1 4 16 64 256)
queue_depth=128
rate=1000

rm url.txt
python generate.py dns_baseline.txt

mkdir dns-result/

for nr_core in $(seq 1 1 8); do 
    echo ">> Test with $nr_core cores >>"

    mkdir dns-result/thp-$nr_core/
    mkdir dns-result/lat-$nr_core/

    for round in $(seq 1 1 10); do
        rm thp-*.txt latency-*.txt
        echo "  >> Test input $rate (Kops) with data size $size Bytes"
        ./build/regex -l 50 -p 03:00.0 -r /tmp/dns_baseline.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
        cat thp-*.txt > dns-result/thp-$nr_core/thp-rate-$round.txt
        cat latency-*.txt > dns-result/lat-$nr_core/lat-rate-$round.txt
        echo "  >> Test done!"
        sleep 2
        rm thp-*.txt latency-*.txt
    done

done