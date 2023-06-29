# data_size=(16 32 64 128 256 512 1024)
data_size=(1024 2048 4096)
dist=(a b c d e f g)
nr_core=$1
start=$2
step=$3
max=$4

for size in "${data_size[@]}"; do
	dir=SHA-${size}B-result/
	mkdir ${dir}

	for i in "${dist[@]}"; do

		mkdir ${dir}/workload${i}/

		for rate in $(seq $start $step $max); do

			mkdir ${dir}/workload${i}/rate-$rate/

			mkdir ${dir}/workload${i}/rate-$rate/thp-$nr_core/
			mkdir ${dir}/workload${i}/rate-$rate/lat-$nr_core/

			workload=workload${i}.spec

			echo "  >> Test input $rate (Kops) with $nr_core on ${workload} ..."
			./build/multiaccel -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -f workload/${workload} -c $nr_core -s $rate -b $size
			mv *-thp-*.txt 		${dir}/workload${i}/rate-$rate/thp-$nr_core/
			mv *-latency-*.txt 	${dir}/workload${i}/rate-$rate/lat-$nr_core/
			echo "  >> Test done!"
			sleep 2
		done
	done
done