mkdir result/

# for nr_core in $(seq 1 1 8); do 
nr_core=8
	echo ">> Test with $nr_core cores >>"

	mkdir result/thp-$nr_core/
	mkdir result/lat-$nr_core/

	for rate in $(seq 10 140 5000); do
		rm thp-*.txt latency-*.txt
		echo "  >> Test input $rate (Kops)"
		./build/sha -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s $rate
		cat thp-*.txt > result/thp-$nr_core/thp-rate-$rate.txt
		cat latency-*.txt > result/lat-$nr_core/lat-rate-$rate.txt
		echo "  >> Test done!"
		sleep 5
	done
# done

rm thp-*.txt latency-*.txt
