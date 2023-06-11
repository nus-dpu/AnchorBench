queue_depth=(1 4 8 32 64 128)
data_size=(20 60 100 200 400)
rate=1000
batch=$1

for depth in "${queue_depth[@]}"; do
	rm thp-*.txt latency-*.txt

	depth_dir=${depth}-wqd
	mkdir ${depth_dir}

	for size in "${data_size[@]}"; do
		rm url.txt
		python generate.py ${size}B_url.txt

		echo ">> Full matching..."

		rm thp-*.txt latency-*.txt

		dir=${depth_dir}/${size}B-full-batch=${batch}-result
		mkdir ${dir}

		for nr_core in $(seq 1 1 8); do 
			echo ">> Full matching | Test with $nr_core cores >>"

			mkdir ${dir}/thp-$nr_core/
			mkdir ${dir}/lat-$nr_core/

			# for round in $(seq 1 1 6); do
				rm thp-*.txt latency-*.txt
				echo "  >> Full matching | Test $size B (round $round)"
				./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q $depth
				cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
				cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
				echo "  >> Test done!"
				sleep 2
			# done
		done
	done
done