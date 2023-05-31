data_size=(16 32 64 128 256 512 1024)
rate=5000

for size in "${data_size[@]}"; do
	mkdir ${size}B-result/

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores and $size B data size >>"

		mkdir ${size}B-result/thp-$nr_core/
		mkdir ${size}B-result/lat-$nr_core/

		for round in $(seq 1 1 10); do
			rm thp-*.txt latency-*.txt
			echo "  >> Test round $round..."
			./build/compress -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s $rate -q 128 -b $size
			cat thp-*.txt > ${size}B-result/thp-$nr_core/thp-rate-$round.txt
			cat latency-*.txt > ${size}B-result/lat-$nr_core/lat-rate-$round.txt
			echo "  >> Test done!"
			sleep 2
		done
	done

	rm thp-*.txt latency-*.txt

done