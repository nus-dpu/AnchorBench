queue_depth=128
data_size=20
batch_size=(1 8 16 32 64)
rate=1000

for size in "${batch_size[@]}"; do
	rm url.txt
	python generate.py ${size}B_url.txt

	echo ">> Partial matching..."

	rm thp-*.txt latency-*.txt
	dir=${size}B-partial-result
	mkdir ${dir}
	
	for nr_core in $(seq 1 1 8); do 
		echo ">> Partial matching | Test with $nr_core cores >>"

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		for round in $(seq 1 1 6); do
			rm thp-*.txt latency-*.txt
			echo "  >> Partial matching | Test $data_size B (round $round)"
			./build/regex -l 50 -p 03:00.0 -r /tmp/partial_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
			cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
			cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
			echo "  >> Test done!"
			sleep 2
		done
	done
done