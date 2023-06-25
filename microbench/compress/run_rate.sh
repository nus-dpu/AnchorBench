data_size=(16 32 64 128 256)
per_core_rate=(100 200 400 800 1200 1600)

for size in "${data_size[@]}"; do
	for rate in "${per_core_rate[@]}"; do

		dir=${size}B-percore=${rate}-result/
		mkdir ${dir}

		for nr_core in $(seq 1 1 4); do 
			echo ">> Test with $nr_core cores >>"

			total_rate=$((nr_core * rate))

			mkdir ${dir}/thp-$nr_core/
			mkdir ${dir}/lat-$nr_core/

			rm thp-*.txt latency-*.txt
			echo "  >> Test input $rate (Kops)"
			./build/compress -l 50 -p 03:00.0 -d $(pwd)/input.dat -c $nr_core -s ${total_rate} -b $size
			mv thp-*.txt		${dir}/thp-$nr_core/
			mv latency-*.txt 	${dir}/lat-$nr_core/
			echo "  >> Test done!"
			sleep 2
		done

		rm thp-*.txt latency-*.txt
	done
done