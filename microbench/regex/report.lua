-- example reporting script which demonstrates a custom
-- done() function that prints latency percentiles as CSV

-- done = function(latency)
--     io.write("------------------------------\n")
--     for _, p in pairs({ 0, 25, 50, 75, 90, 95, 99, 99.3, 99.5, 99.7, 99.9, 99.99, 99.999 }) do
--        n = latency:percentile(p)
--        io.write(string.format("%g%%,%d\n", p, n))
--     end
--  end

print('Hello world!')