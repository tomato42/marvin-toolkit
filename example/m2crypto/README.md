Test harness for M2Crypto python module *without* implicit
rejection a.k.a Marvin workaround, implemented by the underlying OpenSSL.

Usage
=====

Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-alt.sh` script.

Execute reproducer against one of the `ciphers.bin` files, for example the one
for 2048 bit key:
```
python3 timing.py -i rsa2048_repeat/ciphers.bin \
-o rsa2048_repeat/raw_times.csv -k rsa2048/pkcs8.pem -n 256
```

Convert the captured timing information to a format understandable by
the analysis script:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa2048_repeat/log.csv --raw-times rsa2048_repeat/raw_times.csv \
-o rsa2048_repeat/ \
--clock-frequency 1000
```
Since we're using a nanosecond resolution clock in the python script,
we specify the clock frequency as 1000 MHz.

Finally, run the analysis:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa2048_repeat/ --verbose
```

Detailed information about produced output is available in
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
but what's most important is in the summary:
```
Sign test mean p-value: 0.2938, median p-value: 0.1357, min p-value: 1.382e-12
Friedman test (chisquare approximation) for all samples
p-value: 2.8622548800264507e-32
Worst pair: 6(valid_48), 9(valid_repeated_byte_payload_246_1)
Mean of differences: 1.22519e-07s, 95% CI: 5.11834e-08s, 1.960116e-07s (±7.241e-08s)
Median of differences: 1.00000e-07s, 95% CI: 7.80000e-08s, 1.320000e-07s (±2.700e-08s)
Trimmed mean (5%) of differences: 9.03740e-08s, 95% CI: 6.48085e-08s, 1.211334e-07s (±2.816e-08s)
Trimmed mean (25%) of differences: 9.29791e-08s, 95% CI: 7.00548e-08s, 1.186959e-07s (±2.432e-08s)
Trimmed mean (45%) of differences: 9.93611e-08s, 95% CI: 7.54957e-08s, 1.308567e-07s (±2.768e-08s)
Trimean of differences: 9.50000e-08s, 95% CI: 7.33125e-08s, 1.222500e-07s (±2.447e-08s)
For detailed report see rsa2048_repeat_combined/report.csv
Analysis return value: 1
```

The Friedman test p-value specifies how confident is the test in presence of
side channel (the smaller the p-value the more confidant it is, e.g. a
p-value of 1e-6 means 1 in a million chance that there isn't a side-channel).
The other important information are the 95% Confidence Intervals reported,
they specify how sensitive is the script (in this case it's unlikely that
it would be able to detect a side channel smaller than 2.432e-08s or 24ns).
