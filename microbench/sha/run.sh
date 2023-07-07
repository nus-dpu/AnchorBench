data_size=(16 32 64 128 256)
per_core_rate=2500

for size in "${data_size[@]}"; do
	dir=${size}B-result/
	mkdir ${dir}

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		max_rate=$((nr_core * per_core_rate))

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		for rate in $(seq 10 100 ${max_rate}); do
			mkdir ${dir}/thp-$nr_core/rate-$rate/
			mkdir ${dir}/lat-$nr_core/rate-$rate/
			echo "  >> Test input $rate (Kops)"
			./build/sha -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s $rate -b $size
			mv thp-*.txt 		${dir}/thp-$nr_core/rate-$rate/
			mv latency-*.txt 	${dir}/lat-$nr_core/rate-$rate/
			echo "  >> Test done!"
			sleep 2
		done
	done
done