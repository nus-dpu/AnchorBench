data_size=(16 32 64 128 256 512 1024)
rate=5000

for size in "${data_size[@]}"; do
	mkdir ${size}B-result/

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${size}B-result/thp-$nr_core/
		mkdir ${size}B-result/lat-$nr_core/

		rm thp-*.txt latency-*.txt
		echo "  >> Test input..."
		./build/sha -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s $rate -q 128 -b $size
		cat thp-*.txt > ${size}B-result/thp-$nr_core/thp-rate.txt
		cat latency-*.txt > ${size}B-result/lat-$nr_core/lat-rate.txt
		echo "  >> Test done!"
		sleep 2

	done

	rm thp-*.txt latency-*.txt

done