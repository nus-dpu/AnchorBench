# data_size=(16 32 64 128 256 512 1024)
data_size=(2048)

for size in "${data_size[@]}"; do
	dir=SHA=${size}B-result/
	mkdir ${dir}

	for nr_core in $(seq 1 1 1); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		for rate in $(seq 100 100 2000); do
			mkdir ${dir}/thp-$nr_core/rate=$rate
			mkdir ${dir}/lat-$nr_core/rate=$rate

			echo "  >> Test input $rate (Kops)"
			./build/multiaccel -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -f workload/workloada.spec -c $nr_core -s $rate -b $size
			mv *-thp-*.txt 		${dir}/thp-$nr_core/rate=$rate
			mv latency-*.txt 	${dir}/lat-$nr_core/rate=$rate
			echo "  >> Test done!"
			sleep 2
		done
	done

done