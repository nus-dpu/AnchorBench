# queue_depth=(1 4 16 64 256)
data_size=(20)
batch_size=inf
queue_depth=128
nr_core=8

for len in "${data_size[@]}"; do
	python generate.py ${len}B_url.txt

	for size in "${batch_size[@]}"; do
		rm thp-*.txt latency-*.txt

		dir=${len}B-full-batch=${size}-result
		mkdir ${dir}
		
		mkdir ${dir}/thp-$nr_core/
		mkdir ${dir}/lat-$nr_core/

		for rate in $(seq 10 100 5000); do
			mkdir ${dir}/thp-$nr_core/rate-$rate/
			mkdir ${dir}/lat-$nr_core/rate-$rate/

			echo "  >> Test input $rate (Kops) with data size $size Bytes"
			./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a 16
			mv thp-*.txt		${dir}/thp-$nr_core/rate-$rate/
			mv latency-*.txt 	${dir}/lat-$nr_core/rate-$rate/
			echo "  >> Test done!"
			sleep 2
		done
	done
done