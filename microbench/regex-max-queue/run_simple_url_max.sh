queue_depth=128
data_size=(20 60 100 200)
per_core_rate=1000
batch=$1

for size in "${data_size[@]}"; do
	rm url.txt
	python generate.py ${size}B_url.txt

	rm thp-*.txt latency-*.txt
	dir=${size}B-batch=${batch}-result
	mkdir ${dir}
	
	for nr_core in $(seq 1 1 8); do 
		echo ">> Simple matching | Test with $nr_core cores >>"

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

        rate=$((nr_core * per_core_rate))

		# for round in $(seq 1 1 6); do
			rm thp-*.txt latency-*.txt
			echo "  >> Simple matching | Test $data_size B (round $round)"
			./build/regex -l 50 -p 03:00.0 -r /tmp/simple_match_rule.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
			cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 2
		# done
	done

done