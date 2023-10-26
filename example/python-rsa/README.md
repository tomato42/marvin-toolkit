Test harness for python-rsa python module.

Usage
=====

Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-alt.sh` script.

If you are running the script on a system with OpenSSL 3.0 or later,
convert the private key to traditional format:
```
openssl pkey -traditional -in rsa2048/pkcs8.pem -out rsa2048/key.pem
```

Execute reproducer against one of the `ciphers.bin` files, for example the one
for 2048 bit key:
```
python3 timing.py -i rsa2048_repeat/ciphers.bin \
-o rsa2048_repeat/raw_times.csv -k rsa2048/key.pem -n 256
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
Sign test mean p-value: 0.2265, median p-value: 0.06723, min p-value: 6.156e-21
Friedman test (chisquare approximation) for all samples
p-value: 3.2244244003488133e-62
Worst pair: 3(no_structure), 6(valid_48)
Mean of differences: -4.87631e-06s, 95% CI: -7.78079e-06s, -1.817809e-06s (±2.981e-06s)
Median of differences: -1.76900e-06s, 95% CI: -2.15800e-06s, -1.380000e-06s (±3.890e-07s)
Trimmed mean (5%) of differences: -1.96580e-06s, 95% CI: -2.65470e-06s, -1.330388e-06s (±6.622e-07s)
Trimmed mean (25%) of differences: -1.62838e-06s, 95% CI: -1.95745e-06s, -1.240258e-06s (±3.586e-07s)
Trimmed mean (45%) of differences: -1.77149e-06s, 95% CI: -2.10967e-06s, -1.402567e-06s (±3.535e-07s)
Trimean of differences: -1.61550e-06s, 95% CI: -2.02775e-06s, -1.233438e-06s (±3.972e-07s)
```

The Friedman test p-value specifies how confident is the test in presence of
side channel (the smaller the p-value the more confidant it is, e.g. a
p-value of 1e-6 means 1 in a million chance that there isn't a side-channel).
The other important information are the 95% Confidence Intervals reported,
they specify how sensitive is the script (in this case it's unlikely that
it would be able to detect a side channel smaller than 3.535e-07s or 353ns).
