Test harness for RustCrypto rsa crate *without* implicit rejection
a.k.a Marvin workaround.

Usage
=====

Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-alt.sh` script.

Build the harness:
```
cargo build --release
```

Execute reproducer against one of the `ciphers.bin` files, for example the one
for 2048 bit key:
```
cargo run --release -- -i rsa2048_repeat/ciphers.bin \
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
Since we're using a nanosecond resolution clock in the application,
we specify the clock frequency as 1000 MHz.

Finally, run the analysis:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa2048_repeat/ --verbose
```

Detailed information about produced output is available in
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
