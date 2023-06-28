# data_size=(16 32 64 128 256 512 1024)
data_size=(1024 2048 4096)
dist=(a b c d e f g)

for size in "${data_size[@]}"; do
	dir=SHA-${size}B-result/
	mkdir ${dir}

	for i in "${dist[@]}"; do

		mkdir ${dir}/workload${i}/

		for rate in $(seq 100 200 10000); do

			mkdir ${dir}/workload${i}/rate-$rate/

			for nr_core in $(seq 1 1 8); do 
				mkdir ${dir}/workload${i}/rate-$rate/thp-$nr_core/
				mkdir ${dir}/workload${i}/rate-$rate/lat-$nr_core/

				echo "  >> Test input $rate (Kops) with $nr_core..."
				./build/multiaccel -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -f workload/workload${i}.spec -c $nr_core -s $rate -b $size
				mv *-thp-*.txt 		${dir}/workload${i}/rate-$rate/thp-$nr_core/
				mv *-latency-*.txt 	${dir}/workload${i}/rate-$rate/lat-$nr_core/
				echo "  >> Test done!"
				sleep 2
			done
		done

done