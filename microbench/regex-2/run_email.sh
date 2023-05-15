queue_depth=(16 32 64 128 256 512)

for size in "${queue_depth[@]}"; do
	mkdir ${size}wqd-result/

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${size}wqd-result/thp-$nr_core/
		mkdir ${size}wqd-result/lat-$nr_core/

		for rate in $(seq 10 80 4600); do
			rm thp-*.txt latency-*.txt
			echo "  >> Test input $rate (Kops) with data size $size Bytes"
			./build/regex -l 50 -p 03:00.0 -r /tmp/regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q $size
			cat thp-*.txt > ${size}wqd-result/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt > ${size}wqd-result/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 2
		done
	done

	rm thp-*.txt latency-*.txt

done
