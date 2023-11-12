*Very* rough draft of a script to time the decryption of ciphertexts
using the Crypto++ library

Use
===

Run `./step0.sh`, `./step1.sh` as normal. Prepare ciphertexts by
running `./step2-alt.sh` (you might want to comment out generation of
ciphertexts for 1024 and 4096 bit keys as this reproducer doesn't support
them anyway).

Compile the reproducer:
```
g++ -o time_decrypt -lcryptopp time_decrypt.cpp
```

run the reproducer in the main marvin-toolkit directory:
```
example/crypto++/time_decrypt
```

Extract the timing data:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa2048_repeat/log.csv -o rsa2048_repeat \
--raw-times rsa2048_repeat/raw_times.bin --clock-frequency 3699.999 \
--binary 8
```

Remember to set the correct TSC frequency by inspecting `dmesg` output!

**Warning:** None of the clock sources used by the `time_decrypt_legacy.c`
actually run at the same frequency as the CPU frequency! Remember to specify
`--endian big` when running on s390x!

Finally, run the analysis:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa2048_repeat/ --verbose
```

Detailed information about the results, and executing the tests in
an environment that provides statistically significant results faster
are in the
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html).

What's most important is in the summary:
```
Sign test mean p-value: 0.2339, median p-value: 4.255e-12, min p-value: 3.18e-88
Friedman test (chisquare approximation) for all samples
p-value: 0.0
Worst pair: 1(no_header_with_payload_48), 5(valid_0)
Mean of differences: 3.61457e-07s, 95% CI: 2.63026e-07s, 4.577243e-07s (±9.735e-08s)
Median of differences: 4.80000e-07s, 95% CI: 4.30000e-07s, 5.200001e-07s (±4.500e-08s)
Trimmed mean (5%) of differences: 3.84809e-07s, 95% CI: 3.26061e-07s, 4.382825e-07s (±5.611e-08s)
Trimmed mean (25%) of differences: 4.82399e-07s, 95% CI: 4.37442e-07s, 5.255875e-07s (±4.407e-08s)
Trimmed mean (45%) of differences: 4.77529e-07s, 95% CI: 4.31482e-07s, 5.214141e-07s (±4.497e-08s)
Trimean of differences: 4.63125e-07s, 95% CI: 4.07500e-07s, 5.025002e-07s (±4.750e-08s)
Layperson explanation: Definite side-channel detected, implementation is VULNERABLE
For detailed report see rsa2048_repeat/report.csv
Analysis return value: 1
```

The Friedman test p-value specifies how confident is the test in presence of
side channel (the smaller the p-value the more confidant it is, i.e. a
p-value of 1e-6 means 1 in a million chance that there isn't a side-channel).
Here it reports a 0.0, as the value is smaller than possible to represent
using a double precision floating point number (about 2e-308).
The other important information are the 95% Confidence Intervals reported,
they specify how sensitive is the script (in this case it's unlikely that
it would be able to detect a side channel smaller than 4.4e-08s or 44ns).
