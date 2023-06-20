queue_depth=128
rate=1000

rm url.txt
rm thp-*.txt latency-*.txt

dir=20B-100p-result
mkdir ${dir}

python generate.py 20B_url.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Full matching | Test with $nr_core cores >>"

    mkdir ${dir}/thp-$nr_core/
    mkdir ${dir}/lat-$nr_core/

    rm thp-*.txt latency-*.txt
    echo "  >> Full matching | Test $data_size B (round $round)"
    ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
    cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
    cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done

rm url.txt
rm thp-*.txt latency-*.txt

dir=20B-80p-result
mkdir ${dir}

python generate.py 20B_80p_url.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Full matching | Test with $nr_core cores >>"

    mkdir ${dir}/thp-$nr_core/
    mkdir ${dir}/lat-$nr_core/

    rm thp-*.txt latency-*.txt
    echo "  >> Full matching | Test $data_size B (round $round)"
    ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
    cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
    cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done

rm url.txt
rm thp-*.txt latency-*.txt

dir=20B-60p-result
mkdir ${dir}

python generate.py 20B_60p_url.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Full matching | Test with $nr_core cores >>"

    mkdir ${dir}/thp-$nr_core/
    mkdir ${dir}/lat-$nr_core/

    rm thp-*.txt latency-*.txt
    echo "  >> Full matching | Test $data_size B (round $round)"
    ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
    cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
    cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done

rm url.txt
rm thp-*.txt latency-*.txt

dir=20B-40p-result
mkdir ${dir}

python generate.py 20B_40p_url.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Full matching | Test with $nr_core cores >>"

    mkdir ${dir}/thp-$nr_core/
    mkdir ${dir}/lat-$nr_core/

    rm thp-*.txt latency-*.txt
    echo "  >> Full matching | Test $data_size B (round $round)"
    ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
    cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
    cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done

rm url.txt
rm thp-*.txt latency-*.txt

dir=20B-20p-result
mkdir ${dir}

python generate.py 20B_20p_url.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Full matching | Test with $nr_core cores >>"

    mkdir ${dir}/thp-$nr_core/
    mkdir ${dir}/lat-$nr_core/

    rm thp-*.txt latency-*.txt
    echo "  >> Full matching | Test $data_size B (round $round)"
    ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
    cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
    cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done

rm url.txt
rm thp-*.txt latency-*.txt

dir=20B-0p-result
mkdir ${dir}

python generate.py 20B_0p_url.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Full matching | Test with $nr_core cores >>"

    mkdir ${dir}/thp-$nr_core/
    mkdir ${dir}/lat-$nr_core/

    rm thp-*.txt latency-*.txt
    echo "  >> Full matching | Test $data_size B (round $round)"
    ./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth} -a ${size}
    cat thp-*.txt 		> ${dir}/thp-$nr_core/thp-rate-$rate.txt
    cat latency-*.txt 	> ${dir}/lat-$nr_core/lat-rate-$rate.txt
    echo "  >> Test done!"
    sleep 2
done