queue_depth=1
data_size=(20 60 100 200 400)
nr_core=6

for size in "${data_size[@]}"; do
	rm url.txt
	python generate.py ${size}B_url.txt

	echo ">> Full matching..."

	rm thp-*.txt latency-*.txt

	dir=${size}B-imbalance-result
	mkdir ${dir}

	for rate in $(seq 10 120 5000); do 
		echo ">> Full matching | Test with $nr_core cores >>"

		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		# for round in $(seq 1 1 6); do
			rm thp-*.txt latency-*.txt
			echo "  >> Full matching | Test $size B (round $round)"
			./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
			mv thp-*.txt 		${dir}/thp-$nr_core/
			mv latency-*.txt 	${dir}/lat-$nr_core/
			echo "  >> Test done!"
			sleep 2
		# done
	done
done