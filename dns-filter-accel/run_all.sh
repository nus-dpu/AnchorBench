max_rate=10000
for core in $(seq 1 1 7); do
    rate=$((core * 2000))
    if [ "$rate" -gt "${max_rate}" ]; then
        rate=${max_rate}
    fi
    bash run.sh $core 10 100 $rate
done