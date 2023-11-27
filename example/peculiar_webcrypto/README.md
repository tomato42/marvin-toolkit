Test harness for the [@peculiar/webcrypto](https://github.com/PeculiarVentures/webcrypto) module.

Usage
=====

Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-alt.sh` script.

Install needed dependencies:
(this will do it locally, to a newly created `node_modules` directory)
```
npm install commander
npm install @peculiar/webcrypto
```

Execute the reproducer against one of the `ciphers.bin` files, for example
on for 2048 key:
```
node time_decrypt rsa2048_repeat/ciphers.bin rsa2048_repeat/raw_times.bin \
rsa2048/pkcs8.key 256
```

Note: The script will report that pkcs1 depadding errors happened during
execution, but it should still time all the input ciphertexts correctly

Convert the captured timing information to a format understandable by
the analysis script:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa2048_repeat/log.csv --raw-times rsa2048_repeat/raw_times.bin \
--binary 4 -o rsa2048_repeat/ \
--clock-frequency 1000
```

Since we're using a nanosecond resolution clock in the script,
we specify the clock frequency as 1000 MHz.

Finally, run the analysis:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa2048_repeat/ --verbose
```

Detailed information about produced output is available in
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
