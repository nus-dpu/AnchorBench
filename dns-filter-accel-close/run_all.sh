for core in $(seq 1 1 7); do
    rate=$((core * 2000))
    bash run.sh $core 10 100 $rate
done