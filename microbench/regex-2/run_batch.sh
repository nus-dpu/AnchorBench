queue_depth=128
data_size=(20)
batch_size=(1 2 4 8 16 32 64)
per_core_rate=800

for len in "${data_size[@]}"; do
	python generate.py ${len}B_url.txt

	for size in "${batch_size[@]}"; do
		rm thp-*.txt latency-*.txt

		dir=${len}B-full-batch=${size}-percore=${per_core_rate}-result
		mkdir ${dir}
		
		for nr_core in $(seq 1 1 4); do 
			echo ">> Full matching | Test with $nr_core cores >>"

			rate=$((nr_core * per_core_rate))

			mkdir ${dir}/thp-$nr_core/
			mkdir ${dir}/lat-$nr_core/

			rm thp-*.txt latency-*.txt
			echo "  >> Full matching | Test $len B (round $round)"
			./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
			mv thp-*.txt		${dir}/thp-$nr_core/
			mv latency-*.txt 	${dir}/lat-$nr_core/
			echo "  >> Test done!"
			sleep 2
		done
	done
done