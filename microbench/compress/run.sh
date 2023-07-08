data_size=(16 32 64 128 256 512 1024)

for size in "${data_size[@]}"; do
	mkdir ${size}B-result/

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${size}B-result/thp-$nr_core/
		mkdir ${size}B-result/lat-$nr_core/

		for rate in $(seq 10 100 4500); do
			mkdir ${dir}/thp-$nr_core/rate-$rate/
			mkdir ${dir}/lat-$nr_core/rate-$rate/
			echo "  >> Test input $rate (Kops)"
			./build/compress -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s $rate -b $size
			mv thp-*.txt 		${dir}/thp-$nr_core/rate-$rate/
			mv latency-*.txt 	${dir}/lat-$nr_core/rate-$rate/
			echo "  >> Test done!"
			sleep 2
		done
	done
done