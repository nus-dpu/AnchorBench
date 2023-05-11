mkdir long-url-result/

for nr_core in $(seq 1 1 8); do 
	echo ">> Test with $nr_core cores >>"

	mkdir long-url-result/thp-$nr_core/
	mkdir long-url-result/lat-$nr_core/

	for rate in $(seq 10 140 5000); do
		rm thp-*.txt latency-*.txt
		echo "  >> Test long URL input $rate (Kops)"
		./build/regex -l 50 -p 03:00.0 -r /tmp/url_regex_rules.rof2.binary -d $(pwd)/long_url.txt -c $nr_core -s $rate
		cat thp-*.txt > long-url-result/thp-$nr_core/thp-rate-$rate.txt
		cat latency-*.txt > long-url-result/lat-$nr_core/lat-rate-$rate.txt
		echo "  >> Test done!"
		sleep 5
	done
done

rm thp-*.txt latency-*.txt

mkdir short-url-result/

for nr_core in $(seq 1 1 8); do 
	echo ">> Test with $nr_core cores >>"

	mkdir short-url-result/thp-$nr_core/
	mkdir short-url-result/lat-$nr_core/

	for rate in $(seq 10 140 5000); do
		rm thp-*.txt latency-*.txt
		echo "  >> Test short URL input $rate (Kops)"
		./build/regex -l 50 -p 03:00.0 -r /tmp/url_regex_rules.rof2.binary -d $(pwd)/short_url.txt -c $nr_core -s $rate
		cat thp-*.txt > short-urlresult/thp-$nr_core/thp-rate-$rate.txt
		cat latency-*.txt > short-urlresult/lat-$nr_core/lat-rate-$rate.txt
		echo "  >> Test done!"
		sleep 5
	done
done

rm thp-*.txt latency-*.txt
