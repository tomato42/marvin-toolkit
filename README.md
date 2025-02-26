# marvin-toolkit
A set of Linux tools and instructions to check if a library is vulnerable
to the Marvin attack.

Marvin attack is a continuation of work published by Hanno Böck, Juraj
Somorovsky, and Craig Young in their ROBOT Attack[[1]](https://robotattack.org/).

The main page about the attack is at
[https://people.redhat.com/~hkario/marvin/](https://people.redhat.com/~hkario/marvin/)

Version: 0.3.5

Primary contact: Alicja Kario (hkario@redhat.com)

## The vulnerability

Marvin is the extension of the same vulnerability described by Daniel
Bleichenbacher in 1998[[2]](https://link.springer.com/content/pdf/10.1007%2FBFb0055716.pdf)
with the difference being that the used oracle doesn't use the TLS or SSL
alerts to differentiate ciphertexts but rather the time it takes the server
or system under test to process the encrypted RSA message.

Use of non-constant time code, differences in memory accesses, explicit error
handling, etc.—all those things impact the time it takes the system under test
to process a ciphertext.
That means that the library providing the API needs to process the
ciphertext in side-channel free manner, it needs to provide the error to the
application in side-channel free manner, and the application using the API
needs to process the error in side-channel free manner.

If you think that's a lot of side-channel free code, you'd be right.

As side-channel free behaviour is not the typical requirement for written code,
especially outside of cryptographic libraries, it's likely that even if a
piece of code handling RSA decryption was written with side-channel free
behaviour in mind, it wasn't tested for at least constant-timeness.

This is where this toolkit comes in.

## How bad it is?

If an attacker can measure precisely the decryption times of RSA
ciphertexts of their choosing and the side-channel is large, we've shown
decryption of ciphertext possible
in as little as 20 minutes under realistic conditions.

This decryption process may be used for TLS session decryption (if the
attacked session used RSA key exchange or if the session ticket is encrypted
using RSA), e-mail decryption, etc. or forging of signatures.

## Who is affected?

Any application that uses RSA decryption may be vulnerable.
Protocols that use RSA encryption with PKCS#1 v1.5 padding are especially
vulnerable.
RSA OAEP defined in PKCS#1 v2.0 can also be implemented in a way that
leaks enough information to mount a timing attack and decrypt the ciphertext
or forge a signature.

## What's the recommended solution?

As an application programmer: stop using RSA encryption with PKCS#1 v1.5
padding.
If you're a library vendor: stop providing RSA PKCS#1 v1.5 decryption support.
If you do provide RSA OAEP decryption support, you should verify
that it uses big integer arithmetic that is
constant time.
For example, GNU MP does not provide high-level functions for side-channel
free deblinding (multiplication modulo) and OpenSSL BIGNUM doesn't
provide a consistent public interface to perform the de-blinding step and
conversion to a byte string in a side-channel free manner
(see the
[complexity of the fix necessary](https://github.com/openssl/openssl/pull/20281)
to do that using BIGNUM interface).

If deprecation and later removal of the decryption support is not possible,
document the API as known vulnerable.
The users of such an API should be inspected to check if the timing signal
is likely to leak to other processes, VMs or over the network.
The last option being the most severe.
Such applications will need to be fixed.

In case users of the API know a priori what's the expected size of the
decrypted secret, providing an API that generates a random secret of that size
and returns it in case of errors in padding, instead of the decrypted value,
is the recommended way to workaround this vulnerability.
Do note that this works _only_ for online protocols like TLS, as the
returned random value is mixed with the ServerHello.random value, so a
constant result from decryption (in case padding is PKCS#1 v1.5 conforming)
and a random, but same sized, output can behave the same.
See the TLS 1.2 RFC 5246 page 58 for details.
It _will not_ work for cases such like S/MIME (CMS), JSON Web Tokens, XML
encryption, etc.

If neither of those options are realistic, and you've already verified
that the RSA-OAEP interface is side-channel free, you may consider implementing
the workaround described in the Marvin Attack paper.

## Are signatures vulnerable?

To the best of our knowledge APIs for performing RSA signatures,
both RSA-PSS and RSA PKCS#1 v1.5 are not affected.
Though please note that this assumes that the RSA implementation uses blinding
correctly when computing the signature.

That being said, all Bleichenbacher-style attacks can be used to create an
arbitrary signature using the key exposed through the vulnerable decryption
oracle.

## How to test?

To test a library or application, you need to time how long the API call takes
to process ciphertexts of specific form.
You need to test the decryption times repeatedly to collect enough data
for a statistically significant result.
The longer the library takes to process the message with the ciphertext
and the smaller the side-channel is, the
more observations are necessary to show that a library is vulnerable.
In practice, for a local library call, with nanosecond precision timers,
a collection of 100k to a 1M calls per ciphertext are sufficient to
conclusively prove a presence of a side-channel of just dozen nanoseconds.
For a fast library, measuring 10M calls may be enough to show that
if the side channel exists, it's smaller than a single CPU cycle.
For a slow one, with noisy execution, it may take 1G calls or more.
As a rule of thumb, start with 100k and then increase by an order of magnitude
until tests report that the measured confidence iterval becomes too small
for the CPU on which the test was executed.

For a programmer familiar with the decryption API and access to a modern
Linux system, we don't expect the preparation to take more than an hour.
Execution of the tests may take multiple hours or days of machine time.

This toolkit provides 3 tools:

1. A script to generate the RSA keys (in multiple formats)
2. A script to generate the RSA ciphertexts with known plaintext structure
3. A script to analyse the collected results

They have been created with tests running against a local API in mind.
For a script testing the RSA key exchange in TLS, see the
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html).

### Preparation

The provided scripts require modern version of Python (at least 3.7), but they
don't have to be executed on the same machine that executes the timing tests.

To create the virtual environment and install the dependencies, run the
`step0.sh` script.

This script will create a python virtual environment in `marvin-venv`
directory and install all the necessary dependencies for the scripts
to generate ciphertexts and analyse results.

It will also create two more directories: `certgen`—a bash library for
generation of certificates—and `tlsfuzzer`, where the analysis script lives.

It's safe to re-run the script, while it creates those directories it
will not overwrite them or their contents. That also means, if you need to
use newer version of tlsfuzzer, you will need to either update that
git repo checkout manually or delete the directory and re-run the script.

### Generating the certificates

You can generate the certificates using the `step1.sh` script.
It will create three directories: `rsa1024`, `rsa2048` and `rsa4096` with the
key in 3 different formats: old OpenSSL, PKCS#8 and PKCS#12 (the password for
PKCS#12 file is empty). Use whichever one is the easiest to work with with your
application.
It also generates self-signed certificates signed with those keys, in case
the key store requires associating a key with a certificate for use.

You need to pass the certificates to the script generating the ciphertexts.

There is nothing special about those keys, the script is provided only for
convenience.

CAUTION: if you regenerate certificates (re-run the script) you MUST regenerate
the ciphertexts or the test results will be meaningless.

### Generating the ciphertexts

The `step2.py` can generate a wide range of possible ciphertexts, some are
better for checking for vulnerability, others are better at exploiting it.

#### Refresher for PKCS#1 v1.5 encryption

The RSA PKCS#1 v1.5 standard requires the decrypted ciphertext (so,
the plaintext) to have the following format:

```
EM = 0x00 || 0x02 || PS || 0x00 || M
```

Where `EM` stands for encrypted message, `PS` stands for padding string and
`M` is the message for encryption provided by user to the library.

The first byte (0x00) is also called the version byte (though PKCS#1 v2.0
didn't change it).
The second byte (0x02) specifies the padding type, for signatures it's
0x01 and the PS is a repeated 0xff byte. It can also be 0x00 to specify
no padding, but then the first byte of the message must be non-zero.
Padding bytes don't include bytes of value zero.

The minimal size of PS is also specified at 8 bytes.

Thus, a compliant implementation needs to:

1. Perform RSA decryption, convert the integer into a string of bytes
2. Check if the first byte is 0
3. Check if the second byte is 2
4. Look for the zero byte separating the padding string from the message
5. Check if the length of the padding string is at least 8 bytes
6. (Protocol specific) Check if the message has expected length
7. (Protocol specific) Check if the message has specific structure
8. (Protocol specific) In case any tests failed, use the previously generated
   random message of expected length

All those steps must be performed using side-channel free code.

Different ciphertexts exercise different steps of the above list,
some exercise multiple.

#### Selecting ciphertexts

##### Plaintext bit size

Step 1 will most likely be influenced by either the bit length of the
decrypted value or the
[Hamming weight](https://en.wikipedia.org/wiki/Hamming_weight) of the decrypted
value—provided that the correct blinding is used.

Ciphertexts that generate plaintext with bigger than the expected bit
length are:

* `no_structure`
* `no_header_with_payload`, for any message length
* `version_only`
* `version_with_padding`, for any message length
* `type_only`
* `type_with_padding`, for any message length

Ciphertexts that generate plaintext with smaller than the expected bit
length are:

* `signature_type`, for any message length (though it's only by one bit)
* `signature_padding`, for any message length (also only by one bit)
* `no_padding`, for any message size at least 2 bytes smaller than they key
  size in bytes
* `too_short_payload` for any padding_sub bigger than 1

The most extreme of those (thus, most likely to show a timing-side channel)
are the `no_structure` on the high end and the `no_padding` on the low end.
Use small message sizes (<= 48) with `no_padding` for strongest signal.

##### Plaintext Hamming weight

Ciphertexts that generate plaintext with high Hamming weight are:

* `signature_padding` for small message size relative to key size (<= 48 bytes
  as a rule of thumb)
* `valid_repeated_byte_payload` for long message sizes (>= key size/2) and
  a message byte with high Hamming weight (0xff, 0x7f, 0xbf, etc.)

Ciphertexts that generate plaintext with low Hamming weight are:

* `no_padding` for small message sizes (<= key size/2)
* `too_short_payload` for large padding substractions (>= key size/2)
* `valid_repeated_byte_payload` for long message sizes (>= key size/2) and
  a message byte with low Hamming weight (0x00, 0x01, 0x02, etc.)

The most extreme of those are the `signature_padding` with zero-length message
and `valid_repeated_byte_payload` for message size 3 bytes shorter than key
size and a 0x00 message byte.

##### Version byte check

Ciphertexts that generate plaintext with invalid version byte:

* `no_structure`
* `no_header_with_payload`
* `type_only`
* `type_with_padding`

Ciphertexts that generate plaintext with valid version byte:

* `version_only`
* `version_with_padding`
* `signature_type`
* `signature_padding`
* `no_padding`
* `header_only`
* `valid`
* `valid_version`
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`

There shouldn't be any special values for this byte, so testing
`no_structure` and `valid` should be sufficient. Other ciphertexts are
mostly useful in identification of the source of timing signal.

##### Type byte check

Ciphertexts that generate plaintext with invalid type byte:

* `no_structure`
* `no_header_with_payload`
* `version_only`
* `version_with_padding`
* `signature_type`
* `signature_padding`
* `no_padding`, for messages shorter than (key length - 2)
* `too_short_payload`, for non zero padding substraction

Ciphertexts that generate plaintext with valid type byte:

* `type_only`
* `type_with_padding`
* `header_only`
* `valid`
* `valid_version`
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`, for zero padding substraction

There are two special values for the type byte, 0x01 and 0x02, so
it's a good idea to test `valid` for the positive case and both `no_structure`
and `signature_type` or `signature_padding`.

##### Padding byte separator

Ciphertexts that produce plaintext without padding and message separator:

* `no_structure`
* `type_only`
* `header_only`

Ciphertexts that produce plaintext with padding and message separator
(i.e. ones that will have a 0 byte at the position of (key_size -
message_size) of the plaintext):

* `no_header_with_payload`
* `version_with_padding`
* `type_with_padding`
* `signature_type`
* `signature_padding`
* `no_padding`
* `valid`
* `valid_version`
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`

Which ciphertexts are interesting is highly dependent on the specific
implementation. The `no_structure` and `header_only` are generally the best
for negative test cases, but for positive tests it's generally the `valid` and
`no_header_with_payload`, which are the most likely to result in an interesting
timing signal.

##### Padding length check

For padding length check, the implementation can use two algorithms:

1. Look for first non zero byte, consider it a padding type, look for next
   zero byte (this is incorrect)
2. Decrypt the ciphertext, and look at bytes 3 to 10 (inclusive) of plaintext,
   verify that all of them are non-zero (this is the correct approach)

So, below are two sets of ciphertexts, first pair is for the first type of
implementation and the second pair is for the second.

Ciphertexts that produce plaintext with padding of correct length
(that is, a search for a zero in padding will be successful and its
length will be longer than 8 bytes):

* `no_header_with_payload`, for messages shorter than key_size - 10
* `version_with_padding`, for messages shorter than key_size - 10
* `type_with_padding`, for messages shorter than key_size - 10
* `signature_type`, for messages shorter than key_size - 10
* `signature_padding`, for messages shorter than key_size - 10
* `valid`, for messages shorter than key_size - 10
* `valid_version`, for messages shorter than key_size - 10
* `zero_byte_in_padding`, for messages shorter than key_size - 10 and
  zero_byte position higher than 8
* `valid_repeated_byte_payload`, for messages shorter than key_size - 10
* `too_short_payload`, for messages shorter than key_size - 10 - padding_sub

Ciphertexts that produce plaintext with padding of too short length
(though see also "Padding byte separator" for ones where the search doesn't
terminate on 0 byte):

* `no_header_with_payload`, for messages longer than key_size - 10
* `version_with_padding`, for messages longer than key_size - 10
* `type_with_padding`, for messages longer than key_size - 10
* `signature_type`, for messages longer than key_size - 10
* `signature_padding`, for messages longer than key_size - 10
* `no_padding`, though it depends on specifics of implementation
* `valid`, for messages longer than key_size - 10
* `valid_version`, for messages longer than key_size - 10
* `zero_byte_in_padding`, for messages lenger than key_size - 10 and for
  zero_byte positions lower than or equal to 8
* `valid_repeated_byte_payload`, for messages shorter than key_size - 10
* `too_short_payload`, for messages longer than key_size - 10 - padding_sub

For an implementation of the second type,
the ciphertexts that will have no zero bytes
at any of the bytes between 3 and 10 (inclusive) are:

* `no_structure`
* `no_header_with_payload`, for messages shorter than key_size - 10
* `version_only`
* `version_with_padding`, for messages shorter than key_size - 10
* `type_only`
* `type_with_padding`, for messages shorter than key_size - 10
* `signature_type`, for messages shorter than key_size - 10
* `signature_padding`, for messages shorter than key_size - 10
* `no_padding`, for messages longer or equal to than key_size - 2, though
  there is a non-zero chance that it will have zero bytes, avoid this
  ciphertext for this test
* `header_only`
* `valid`, for messages shorter than key_size - 10
* `valid_version`, for messages shorter than key_size - 10
* `zero_byte_in_padding`, for messages shorter than key_size - 10 and
  zero_byte position higher than 8
* `valid_repeated_byte_payload`, for messages shorter than key_size - 10
* `too_short_payload`, for messages shorter than key_size - 10 and padding
  substraction equal 0 or 1

Here, the two probes that are most likely to give consistent results are the
`zero_byte_in_padding` with a reasonable message length (<= 48 bytes) and
zero_byte position between 0 and 8 inclusive. For positive tests, use
`valid` with a message of same length.

##### Message length check

For checking if the library correctly tests the length of the message, or
if the length of the message doesn't provide a side channel, use
one of the probes that allow setting the length of the message:

* `no_header_with_payload`
* `version_with_padding`
* `type_with_padding`
* `signature_type`
* `signature_padding`
* `no_padding`
* `valid`
* `valid_version`
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`

The probe that is least likely to provide a false signal is the `valid` one.
You should test different lengths, from 0 (including 0) up to the max size
supported by the key (key_length - 10), and at least a few in between: typical
sizes for symmetric key sizes: 16, 24, 32, 48, some that may cause buffer
overflow: 1, 2, 4, as well as 128, 192, 256 (if supported by given key size).
See also CVE-2012-5081.

##### Custom structure

In case the protocol requires specific structure of the encrypted message,
we can only suggest modifying the `step2.py` script to generate random
messages that follow it.

For TLS, which requires two first bytes of the message to equal the negotiated
version, you should use the
[test-bleichenbacher-timing-pregenerate.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-bleichenbacher-timing-pregenerate.py)
script from tlsfuzzer.
See [tlsfuzzer documenation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
for instructions how to execute it.

##### Verifying correctness of ciphertexts

If you want to check if the encrypted values are indeed in the format
described in the preceding paragraphs, you can use the OpenSSL command line
tool:

To check if the ciphertext is indeed valid PKCS#1 v1.5 ciphertext run
(for example):
```
openssl rsautl -decrypt -pkcs -inkey rsa1024/key.pem \
-in rsa1024_ciphertexts/valid_48 -hexdump
```
With the following output:
```
0000 - a9 39 19 2c a0 06 6f 88-25 b9 5d 1c 98 2a 7c 5c   .9.,..o.%.]..*|\
0010 - 36 51 30 db 28 ed 5b 59-f9 4e 67 54 5f e5 07 1e   6Q0.(.[Y.NgT_...
0020 - 50 14 6c b5 ab 87 14 e5-e1 8c b3 08 fe 64 0c 69   P.l..........d.i
```

When testing an invalid ciphertext:
```
openssl rsautl -decrypt -pkcs -inkey rsa1024/key.pem \
-in rsa1024_ciphertexts/no_structure -hexdump
```
The output will look something like this (if openssl doesn't support implicit
rejection):
```
140518003775296:error:0407109F:rsa routines:RSA_padding_check_PKCS1_type_2:pkcs decoding error:crypto/rsa/rsa_pk1.c:251:
140518003775296:error:04065072:rsa routines:rsa_ossl_private_decrypt:padding check failed:crypto/rsa/rsa_ossl.c:549:
```

To verify that invalid ciphertexts have the specified structure, use the `-raw`
option:
```
openssl rsautl -decrypt -raw -inkey rsa1024/key.pem \
-in rsa1024_ciphertexts/header_only -hexdump
```
That will produce output similar to this one:
```
0000 - 00 02 57 74 a6 34 62 59-41 21 56 36 13 3e d0 a3   ..Wt.4bYA!V6.>..
0010 - e5 3e 6b 9a 1f 35 37 cf-9a 56 84 db 7f 89 a5 b5   .>k..57..V......
0020 - f4 69 9a 8c e7 e9 a0 1f-27 ba f9 53 64 d9 64 21   .i......'..Sd.d!
0030 - 75 60 83 07 1c 49 39 fa-8a 6e 72 35 be ef 02 e1   u`...I9..nr5....
0040 - a3 dd 18 a8 09 79 45 3c-2a e0 23 12 d1 17 f5 62   .....yE<*.#....b
0050 - 73 b0 88 55 2c 59 81 37-3c 69 56 bd c6 41 13 12   s..U,Y.7<iV..A..
0060 - e8 ef 78 fa 12 93 0a 09-51 0a 94 12 40 93 eb 52   ..x.....Q...@..R
0070 - 88 0f fd 25 3c 91 31 4e-a2 b7 c5 1c ea 1f 60 2c   ...%<.1N......`,
```
(note that there's only one 0x00 byte: the very first one)

##### Summary

Given the above notes, we suggest running the following set of probes to
look for side channels in an implementation:

* `no_structure`
* `no_padding` with message length 48
* `signature_padding` with message length 8
* `valid_repeated_byte_payload` with message 10 bytes shorter than key and
  0x00 as message byte
* `valid` with message length 48
* `header_only`
* `no_header_with_payload` with message length 48
* `zero_byte_in_padding` with message length 48 and zero_byte of 4
* `valid` with message length 0, 192, and key_length - 10
* Optionally: also `valid` with message length 1, 2, 16, 32, and 128
* Optionally: `too_short_payload` with padding too short by 1, 3, 7, and 15
  bytes

In case the protocol you're testing requires a specific message length, change
the length from 48 to the required length and add the 48 to the last set of
probes.

In case you're testing the TLS specific decoder, use also `valid_version`
with length of 48, and the two bytes specifying correct protocol version
(3, 3 for TLS 1.2).

Use the following commands to generate them for the previously generated keys:
```
PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa1024/cert.pem -o rsa1024_ciphertexts \
no_structure no_padding=48 signature_padding=8 \
valid_repeated_byte_payload="118 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=118
PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa2048/cert.pem -o rsa2048_ciphertexts \
no_structure no_padding=48 signature_padding=8 \
valid_repeated_byte_payload="246 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=192 valid=246
PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa4096/cert.pem -o rsa4096_ciphertexts \
no_structure no_padding=48 signature_padding=8 \
valid_repeated_byte_payload="502 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=192 valid=502
```

or run `step2.sh`.

You'll find the ciphertexts in the `rsa1024_ciphertexts`,
`rsa2048_ciphertexts`, and `rsa4096_ciphertexts` directories.

Use other probes or other parameters when you find a timing signal and want
to pin-point the likely incorrectly implemented check.

To make it easier to process the ciphertext in random order, in way that the
test harness doesn't contribute to the side-channel, you can alternatively
execute the `step2-alt.sh`.

Or add the command line options `--repeat 100000 --verbose` before the `-c`
option. This will generate a single `ciphers.bin` that is a concatenation
of ciphertexts in random order. The order of them is saved in `log.csv`
file.

For testing OAEP interface, use the following ciphertexts:

* `no_structure`
* `valid` (any length)
* `too_short_payload` with message size 0 and padding shorter by 1, 3, 7, and
  15 bytes
* `no_padding` with short message size (<= 48 bytes)
* `signature_padding` with message length 8
* `valid_repeated_byte_payload` with message 11 bytes shorter than key and
  0x00 as message byte

Or run the `step2-oaep-alt.sh` script.

### Writing the test harness

The test harness should load the private key and the associated ciphertexts.

It should try to decrypt each ciphertext in turn and measure the time it
takes to decrypt the given ciphertext.
If the used API can throw exceptions, those should be caught and silently
ignored.

You should execute the ciphertexts in sets, in random order.
The harness itself should be side-channel free (for example, the
memory location of the ciphertext must not be correlated with the plaintex).
This kind of execution will minimize the effect of the systemic error and
is necessary for the validity of the following statistical analysis.

The easiest way to have a side-channel free harness, is to split it to two
parts: one part which writes the ciphertexts to be processed to a file
in random order (saving the order in which they are processed) and
the second part which blindly reads those ciphertexts from a file and
processes them in order (remember that ciphertexts are the same size
as the RSA modulus, and APIs must accept zero padded ciphertexts, so
each ciphertext is the exact same size).

Save the resulting execution times to a `timing.csv` file, where each column
corresponds to collected times for a given ciphertext.
You can use any unit (seconds, nanoseconds, clock ticks), but the
subsequent analysis generates graphs expecting seconds so it's a good
idea to normalise the values to seconds for readability.

Alternatively you can dump raw values read from a constantly ticking clock
source (like TSC in any modern x86\_64 cpu) and then use the
``--binary`` together with ``--clock-frequency`` option of ``extract.py``.
As that is usually easier to do in side-channel free manner, it's the
recommended approach.

See following python pseudo-code for the principle of operation, but
with non side-channel free harness:
```python
# put the probe you want as the reference point of analysis first
ciphertexts = {"header_only": b"\x2f...",
               "no_padding_48": b"\xbc...",
               ...}

names = list(ciphertexts.keys())
times = {key: list() for key in names}

for i in range(10000):
    random.shuffle(names)
    for id in names:
        ciph = ciphertexts[id]
        # be wary of rounding in clock APIs that return floating point numbers!
        start_time = time.perf_counter_ns()
        try:
            # query the oracle
            priv_key.decrypt(ciph)
        except Exception:
            pass
        dec_time = time.perf_counter_ns() - start_time

        # convert ns to s
        # remember that single precision IEEE 754 floating point numbers provide
        # only 7 decimal digits or precision, in general we need at least 9,
        # i.e.: use "double" not "float" or "binary32"
        dec_time = dec_time / 1.e9

        times[id].append(dec_time)

with open("timing.csv", "w") as f_out:
    f_out.write(",".join(names)) + "\n")
    for i in range(len(times[names[0]])):
        f_out.write(",".join(str(times[name][i]) for name in names) + "\n")
```

See the
[test-bleichenbacher-timing-pregenerate.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-bleichenbacher-timing-pregenerate.py)
for an example script that first generates random ciphertexts and then
reads them from a file.

Alternatively use the `step2-alt.sh` or `step2-oaep-alt.sh` with example
test harnesses in the `example` directory.

### Running the test

The test can be executed on any machine, the statistical analysis is
constructed in a way that it will work correctly even with noisy data,
processes running in the background, etc.

That being said, the less noise, the quicker the values and confidence
intervals will converge to small enough values (<1ns or 1 CPU cycle) to
confidently say "it's not possible to show presence of a timing side-channel".

See
[tlsfuzzer documenation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html#environment-setup)
if you want to prepare an especially quiet environment.

### Analysing the results

As the analysis generates multiple files and graphs, we recommend organizing
different `timing.csv` files into different directories.

Execute the analysis using the following command:
```
PYTHONPATH=tlsfuzzer marvin-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
-o path_to_dir_with_timing.csv/
```

The script will generate multiple files and graphs that describe the
measured times.

The most important file is the `report.txt` file, containing,
among other values, the result of the
[Friedman test](https://en.wikipedia.org/wiki/Friedman_test) on collected
samples.
In case there is no detectable timing side channel for the given sample size,
the p-value of it will be bigger than 0.05.
If the value is smaller than that, then there's likely a side channel and
re-runing with a larger sample size is recommended.
If it reports p-value smaller than 1e-9, then it's almost certain that
a timing side-channel exists.

To determine how big the possible side channel is, check the values for the
worst pair of measurements. The median difference is the most robust
estimator of it (together with its Confidence Interval), but is limited by the
resolution of the clock used.
If you see a median of 0s with a 95% CI of 0, and you have used a clock with
nanosecond precision or better, then it's almost certain
that there is no side-channel present.
If your clock source is ticking at significantly lower frequency than the
CPU frequency
(common on the ARM platform), then looking at trimmed mean is generally a
good idea. Its interpretation is the same as the median, but it will be able
to interpolate the size of side-channels smaller than the clock tick.

To decrease the CI by an order of magnitude (e.g. from 100ns to 10ns), you
will need to execute a run with 100 times more observations (in general,
the measurement error falls with a square root of sample size).

We found that the mean of differences estimator is very slow to converge in case
of a noisy environment.

See [tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html#interpreting-the-results)
on how to interpret the other results or the generated graphs.

Note: the analysis is computationally intensive, for samples with tens of
millions of observations it may take hours!
It is also implemented to use multiple CPU cores efficiently, but that
increases the memory usage significantly (for a machine with 128 CPU cores
analysing 36 samples, 10 million observations each, you will need around
128 GB of RAM).
You can limit parallelizm by using ``--workers`` command line option.

#### False positives

If your test harness is constant time, and you've tested the individual
ciphertexts in random order, then there's still one place where a false
positive signal may come from: processing the _ciphertext_ value.

If the numerical library is not constant time, then multiplying the same
ciphertext over and over may provide enough of a signal to differentiate it
from some other ciphertext with a slightly different structure, even
if they decrypt to functionally identical plaintext.

The way around it is to use random ciphertexts that decrypt to
functionally identical plaintexts (i.e. if we're testing how an implemntation
handles a zero byte at 5th byte of the plaintext, values of the rest of
``PS`` or message don't matter, they can be random for every decryption)
for each and every decryption.
See
[test-bleichenbacher-timing-pregenerate.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-bleichenbacher-timing-pregenerate.py)
for a practical example of a script that does that.
Or use the `--repeat` option with the `./step2.py` script.
