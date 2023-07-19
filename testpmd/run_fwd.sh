nr_core=[1,2,3,4,5,6,7]
for core in "${nr_core[@]}"; do
    mkdir thp-$core/

    echo ">> Test with $nr_core cores >>"

    rm thp-*.txt
    ./build/testpmd -l 0-$core -n 4 -a 03:00.0 -- -m "[1-$core:1-$core].0"
    mv thp-*.txt            thp-$core/
    echo "  >> Test done!"
    sleep 2

done