queue_depth=128
size=20
nr_core=8
rate=400

rm url.txt
python generate.py ${size}B_url.txt

echo ">> Full matching..."

rm thp-*.txt latency-*.txt

dir=${size}B-full-imbalance-result
mkdir ${dir}

echo ">> Full matching | Test at rate $rate >>"

rm thp-*.txt latency-*.txt
echo "  >> Full matching | Test $size B"
./build/regex -l 50 -p 03:00.0 -r /tmp/full_url_regex_rules.rof2.binary -d $(pwd)/input.txt -c $nr_core -s $rate -q ${queue_depth}
mv thp-*.txt 		${dir}/
