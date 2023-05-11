data_size=(16 32 64 128 256 512 1024)

for size in "${data_size[@]}"; do
	mkdir ${size}B-result/

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${size}B-result/thp-$nr_core/
		mkdir ${size}B-result/lat-$nr_core/

		for rate in $(seq 10 140 5000); do
			rm thp-*.txt latency-*.txt
			echo "  >> Test input $rate (Kops) with data size $size Bytes"
			./build/regex -l 50 -p 03:00.0 -r /tmp/regex_rules.rof2.binary -d $(pwd)/alice_in_wonderland.txt -c $nr_core -s $rate -b $size
			cat thp-*.txt > ${size}B-result/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt > ${size}B-result/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 5
		done
	done

	rm thp-*.txt latency-*.txt

done