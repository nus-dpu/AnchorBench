queue_depth=128
data_size=(20 60 100 200)
batch_size=(1 2 4 8 12 16 20 24 28 32 36 40 44 48 52 56 60 64)
# batch_size=inf

for len in "${data_size[@]}"; do
	python generate.py ${len}B_url.txt

	for rate in $(seq 10 100 2000); do

		for size in "${batch_size[@]}"; do
			rm thp-*.txt latency-*.txt

			dir=${len}B-full-batch=${size}-rate=${rate}-result
			mkdir ${dir}
			
			for nr_core in $(seq 1 1 4); do 
				echo ">> Full matching | Test with $nr_core cores >>"

				mkdir ${dir}/thp-$nr_core/
				mkdir ${dir}/lat-$nr_core/

				rm thp-*.txt latency-*.txt
				echo "  >> Full matching | Test $len B (round $round)"
				# ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a 1
				./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
				mov thp-*.txt		${dir}/thp-$nr_core/
				mov latency-*.txt 	${dir}/lat-$nr_core/
				echo "  >> Test done!"
				sleep 2
			done
		done
	done
done