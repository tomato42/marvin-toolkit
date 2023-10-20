Test harness for pyca/cryptography python module *without* implicit
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

Detailed information about produced output is available in (tlsfuzzer
documentation)[https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html]
but what's most important is in the summary:
```
Sign test mean p-value: 0.5538, median p-value: 0.562, min p-value: 0.06575
Friedman test (chisquare approximation) for all samples
p-value: 0.9617988327160067
Worst pair: 8(valid_246), 11(zero_byte_in_padding_48_4)
Mean of differences: -2.59050e-07s, 95% CI: -4.24877e-06s, 3.403219e-06s (±3.826e-06s)
Median of differences: -4.29572e-08s, 95% CI: -9.08922e-08s, 5.531000e-09s (±4.821e-08s)
Trimmed mean (5%) of differences: -3.89065e-07s, 95% CI: -1.18398e-06s, 3.069665e-07s (±7.455e-07s)
Trimmed mean (25%) of differences: -6.51617e-08s, 95% CI: -1.41947e-07s, 1.304047e-08s (±7.749e-08s)
Trimmed mean (45%) of differences: -4.19826e-08s, 95% CI: -9.36116e-08s, 8.553458e-09s (±5.108e-08s)
Trimean of differences: -4.15053e-08s, 95% CI: -9.20906e-08s, 9.241294e-09s (±5.067e-08s)
For detailed report see rsa2048_repeat/report.csv
Analysis return value: 0
```

The Friedman test p-value specifies how confident is the test in presence of
side channel (the smaller the p-value the more confidant it is, e.g. a
p-value of 1e-6 means 1 in a million chance that there isn't a side-channel).
The other important information are the 95% Confidence Intervals reported,
they specify how sensitive is the script (in this case it's unlikely that
it would be able to detect a side channel smaller than 4.821e-08s or 48ns).
