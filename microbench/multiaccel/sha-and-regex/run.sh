# data_size=(16 32 64 128 256 512 1024)
data_size=(2048)

for size in "${data_size[@]}"; do
	dir=SHA-${size}B-result/
	mkdir ${dir}

	for rate in $(seq 100 100 3000); do
		mkdir ${dir}/rate-$rate/

		for nr_core in $(seq 1 1 1); do 
			mkdir ${dir}/rate-$rate/thp-$nr_core/
			mkdir ${dir}/rate-$rate/lat-$nr_core/

			echo "  >> Test input $rate (Kops) with $nr_core..."
			./build/multiaccel -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -f workload/workloada.spec -c $nr_core -s $rate -b $size
			mv *-thp-*.txt 		${dir}/rate-$rate/thp-$nr_core/
			mv latency-*.txt 	${dir}/rate-$rate/lat-$nr_core/
			echo "  >> Test done!"
			sleep 2
		done
	done

done