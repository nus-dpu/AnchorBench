queue_depth=128
data_size=(20 30 60 100 200 400)
rate=1000

for size in "${data_size[@]}"; do
	rm url.txt
	python generate.py ${size}B_url.txt

	echo ">> Partial matching..."

	rm thp-*.txt latency-*.txt
	dir=${size}B-partial-result
	mkdir ${dir}
	
	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		for round in $(seq 1 1 10); do
			rm thp-*.txt latency-*.txt
			echo "  >> Test input $rate (Kops) with data size $size Bytes"
			./build/regex -l 50 -p 03:00.0 -r /tmp/partial_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
			cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 2
		done
	done

	echo ">> Full matching..."

	rm thp-*.txt latency-*.txt
	dir=${size}B-full-result
	mkdir ${dir}

	for nr_core in $(seq 1 1 8); do 
		echo ">> Test with $nr_core cores >>"

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		for round in $(seq 1 1 10); do
			rm thp-*.txt latency-*.txt
			echo "  >> Test input $rate (Kops) with data size $size Bytes"
			./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
			cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 2
		done
	done

	rm thp-*.txt latency-*.txt

done