Test script for TPM 2

Prerequisites
-------------

The TPM 2 test script loads the RSA key into the TPM's NULL hierarchy. Please
make sure that the NULL hierarchy has no password set and no other
application is using the TPM 2 and sufficient space is available in the TPM for
loading the RSA key. Since access to TPM devices is typically restricted to the
root user, the test script (time_decrypt) will need to be run as root.

The TPM 2 test script can for example be run against swtpm using the vtpm
proxy device:

 > modprobe tpm_vtpm_proxy
 > swtpm chardev --vtpm-proxy --tpmstate dir=./ --tpm2
 New TPM device: /dev/tpm1 (major/minor = 253/1)

For the test script to use the proper device, which would be /dev/tpmrm1,
set the following environment variable:

 TPM_DEVICE=/dev/tpmrm1


When using a hardware TPM 2 the following should be used:

 TPM_DEVICE=/dev/tpmrm0

The following packages are needed:

 - openssl-devel / libssl-dev
 - tss2-devel / libtss2-dev
 - swtpm-tools


OpenSSL *with* implicit rejection
=================================
Test harness for OpenSSL *with* implicit rejection a.k.a Marvin workaround.

Usage
-----

Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-marvin.sh` script.

Compile this reproducer:
```
gcc -o time_decrypt time_decrypt.c -lcrypto -libmtss
```

Execute it against one of the `pms_values.bin` files, for either 1024
(-n 128) or 2048 bit (-n 256):
```
TPM_DEVICE=/dev/tpmrm1 TPM_INTERFACE_TYPE=dev ./time_decrypt \
-i rsa2048_repeat/pms_values.bin -o rsa2048_repeat/raw_times.bin \
-k rsa2048/pkcs8.pem -n 256
```

Note:
If swtpm is **mistakenly** used with a version of OpenSSL that does not
implement implicit rejection ('older' versions, e.g. OpenSSL 1.1.1), then
the TPM 2 will return error messages when a decryption failure occurs
(e.g., detected bad padding) and the output may show the following:

```
finished  total: 22000 decryption failures: 16000  unexpected msg len: 0
```

Newer versions of OpenSSL with implicit rejection support will not indicate
decryption failures but return a message leading to the following output:

```
finished  total: 22000 decryption failures: 0  unexpected msg len: 0
```

Convert the captured timing information to a format understandable by
the analysis script:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa2048_repeat/log.csv --raw-times rsa2048_repeat/raw_times.bin \
-o rsa2048_repeat/ \
--binary 8 --endian little --clock-frequency 2712.003
```
The `--clock-frequency` is the TSC frequency, as reported by the kernel on
my machine:
```
[    1.506811] tsc: Refined TSC clocksource calibration: 2712.003 MHz
```
Specifying it is optional, but then the analysis will interpret clock
ticks as seconds so interpretation of the results and graphs in terms of
CPU clock cycles will be more complex.

**Warning:** None of the clock sources used by the `time_decrypt_legacy.c`
actually run at the same frequency as the CPU frequency! Remember to specify
`--endian big` when running on s390x!

Finally, run the analysis:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa2048_repeat/ --verbose
```

OpenSSL *without* implicit rejection
====================================
Test harness for OpenSSL *without* implicit rejection a.k.a Marvin workaround.

Usage
-----

Run `step0.sh`, `step1.sh` as normal. Instead of running `step2.sh` run
the `step2-alt.sh` script.

Compile this reproducer:
```
gcc -o time_decrypt time_decrypt.c -lcrypto -libmtss
```

Execute it against one of the `ciphers.bin` files, for example the one
for 2048 bit key:
```
TPM_DEVICE=/dev/tpmrm1 TPM_INTERFACE_TYPE=dev ./time_decrypt \
-i rsa2048_repeat/ciphers.bin -o rsa2048_repeat/raw_times.bin \
-k rsa2048/pkcs8.pem -n 256
```

Note:
If swtpm is **mistakenly** used with a version of OpenSSL that implements
implicit rejection ('newer' versions), then the TPM 2 will return
decrypted messages of unexpected length but not indicate any decrytption
failures:

```
finished  total: 1200000 decryption failures: 0  unexpected msg len: 1096285
```

Older versions of OpenSSL without implicit rejection will indicate
decryption failures as well as messages of unexpected length:

```
finished  total: 1200000 decryption failures: 900000  unexpected msg len: 200000
```

Convert the captured timing information to a format understandable by
the analysis script:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa2048_repeat/log.csv --raw-times rsa2048_repeat/raw_times.bin \
-o rsa2048_repeat/ \
--binary 8 --endian little --clock-frequency 2712.003
```
The `--clock-frequency` is the TSC frequency, as reported by the kernel on
my machine:
```
[    1.506811] tsc: Refined TSC clocksource calibration: 2712.003 MHz
```
Specifying it is optional, but then the analysis will interpret clock
ticks as seconds so interpretation of the results and graphs in terms of
CPU clock cycles will be more complex.

**Warning:** None of the clock sources used by the `time_decrypt.c`
actually run at the same frequency as the CPU frequency! Remember to specify
`--endian big` when running on s390x!

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
Sign test mean p-value: 0.562, median p-value: 0.5909, min p-value: 0.01485
Friedman test (chisquare approximation) for all samples
p-value: 0.8505764327569006
Worst pair: 3(invalid version number (1) in padding), 21(zero byte in third byte of padding)
Mean of differences: -1.15477e-06s, 95% CI: -2.39868e-06s, -1.775660e-07s (±1.111e-06s)
Median of differences: -1.15235e-06s, 95% CI: -1.93374e-06s, -2.008180e-07s (±8.665e-07s)
Trimmed mean (5%) of differences: -1.06137e-06s, 95% CI: -2.07415e-06s, -2.513678e-07s (±9.114e-07s)
Trimmed mean (25%) of differences: -9.13984e-07s, 95% CI: -1.75922e-06s, -1.177341e-07s (±8.207e-07s)
Trimmed mean (45%) of differences: -1.02560e-06s, 95% CI: -1.90639e-06s, -1.207689e-07s (±8.928e-07s)
Trimean of differences: -8.79908e-07s, 95% CI: -1.74172e-06s, -1.827706e-07s (±7.795e-07s)
Layperson explanation: Large confidence intervals detected, collecting more data necessary. Side channel leakege smaller than 8.207e-07s is possible
For detailed report see rsa2048_repeat/report.csv
Analysis return value: 0
```

The Friedman test p-value specifies how confident is the test in presence of
side channel (the smaller the p-value the more confident it is, i.e. a
p-value of 1e-6 means 1 in a million chance that there isn't a side-channel).
The other important information is the 95% Confidence Intervals reported,
it specifies how sensitive the script is (in this case it's unlikely that
it would be able to detect a side channel smaller than 8.665e-07s or 866ns).
