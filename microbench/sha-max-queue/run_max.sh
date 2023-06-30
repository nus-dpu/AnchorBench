data_size=(16 32 64 128 256 512 1024 2048 4096 8192 16384 32768)
rate=1000

for size in "${data_size[@]}"; do
	mkdir ${size}B-result/

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${size}B-result/thp-$nr_core/
		mkdir ${size}B-result/lat-$nr_core/

		for round in $(seq 1 1 10); do
			rm thp-*.txt latency-*.txt
			echo "  >> Test $data_size B (round $round)"
			./build/sha -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s $rate -b $size
			cat thp-*.txt > ${size}B-result/thp-$nr_core/thp-rate-$round.txt
			cat latency-*.txt > ${size}B-result/lat-$nr_core/lat-rate-$round.txt
			echo "  >> Test done!"
			sleep 5
		done
	done

	rm thp-*.txt latency-*.txt

done