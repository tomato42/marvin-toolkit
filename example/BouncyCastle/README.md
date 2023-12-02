Test scripts for BouncyCastle Java implementation.

Usage
=====

PKCS#1 v1.5 API
---------------
Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-alt.sh` script.

Download the bcprov jar from the releases page:
https://www.bouncycastle.org/latest_releases.html

Compile the reproducer:
```
javac -cp bcprov-jdk18on-177.jar:. PKCS1Decryption.java
```

Execute it against one of the `pms_values.bin` files, for example the one
for 2048 bit key:
```
java -cp bcprov-jdk18on-177.jar:. PKCS1Decryption \
rsa2048/key.key rsa2048_repeat/ciphers.bin rsa2048_repeat/raw_times.csv 256
```

RSA-OAEP
--------
Instead of running `step2.sh` run the `step2-oaep-alt.sh`
(there is no need to rerun step0 or step1 scripts).

Download the bcprov jar from the releases page:
https://www.bouncycastle.org/latest_releases.html

Compile the reproducer:
```
javac -cp bcprov-jdk18on-177.jar:. OAEPDecryption.java
```

Execute it against one of the `pms_values.bin` files, for example the one
for 2048 bit key:
```
java -cp bcprov-jdk18on-177.jar:. OAEPDecryption \
rsa2048/key.key rsa2048_repeat/ciphers.bin rsa2048_repeat/raw_times.csv 256
```

Analysis
--------

Convert the captured timing information to a format understandable by
the analysis script:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa2048_repeat/log.csv --raw-times rsa2048_repeat/raw_times.csv \
-o rsa2048_repeat/ \
--clock-frequency 1000.00
```
Since we use nanosecond resolution clock, we specify 1000 MHz clock frequency.

Finally, run the analysis:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa2048_repeat/ --verbose
```

Interpretation of results
=========================

Detailed information about produced output is available in
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
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
side channel (the smaller the p-value the more confidant it is, i.e. a
p-value of 1e-6 means 1 in a million chance that there isn't a side-channel).
The other important information are the 95% Confidence Intervals reported,
they specify how sensitive is the script (in this case it's unlikely that
it would be able to detect a side channel smaller than 4.821e-08s or 48ns).
