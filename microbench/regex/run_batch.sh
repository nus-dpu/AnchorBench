queue_depth=128
data_size=(20 60 100 200)
batch_size=(2 4 8 16 32 64 128)
rate=1000

for len in "${data_size[@]}"; do
	python generate.py ${len}B_url.txt

	for size in "${batch_size[@]}"; do
		rm thp-*.txt latency-*.txt

		dir=${len}B-full-batch=${size}-result
		mkdir ${dir}
		
		for nr_core in $(seq 1 1 8); do 
			echo ">> Full matching | Test with $nr_core cores >>"

			mkdir ${dir}/thp-$nr_core/
			mkdir ${dir}/lat-$nr_core/

			rm thp-*.txt latency-*.txt
			echo "  >> Full matching | Test $len B (round $round)"
			./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
			cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 2
		done
	done
done