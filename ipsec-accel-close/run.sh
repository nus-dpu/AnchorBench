nr_core=$1
step=$2
max_rate=$3

mkdir thp-$nr_core/

echo ">> Test with $nr_core cores >>"

for rate in $(seq 10 $step $max_rate); do
    echo ">> Rate at $rate... >>"
    rm thp-*.txt
    ./build/ipsec -l 0-${nr_core} -n 4 -a 03:00.0 -a 03:00.1 -- -m "[1-$nr_core:-].0,[-:1-$nr_core].1" -- -l 50 -p 03:00.0
    cat thp-*.txt > thp-$nr_core/thp-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done
rm thp-*.txt