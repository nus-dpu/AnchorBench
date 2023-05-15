mkdir email-result/

rm url.txt
python generate.py email_addr.txt

for nr_core in $(seq 1 1 8); do 
    echo ">> Test with $nr_core cores >>"

    mkdir email-result/thp-$nr_core/
    mkdir email-result/lat-$nr_core/

    for rate in $(seq 10 140 5000); do
        rm thp-*.txt latency-*.txt
        echo "  >> Test input $rate (Kops)"
        ./build/regex -l 50 -p 03:00.0 -r /tmp/email_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate
        cat thp-*.txt > email-result/thp-$nr_core/thp-rate-$rate.txt
        cat latency-*.txt > email-result/lat-$nr_core/lat-rate-$rate.txt
        echo "  >> Test done!"
        sleep 5
    done
done

rm thp-*.txt latency-*.txt
