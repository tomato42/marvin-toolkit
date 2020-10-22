# EMBARGOED ISSUE

This issue is currently embargoed. You're free to use the toolkit to find,
fix bugs, and release new versions with the fixes. That is, we do not aim
for coordinated disclosure.
At the same time we'd like to ask you from discussing publicly the complete
scope of the issue. That is, please
talk publicly about "Fix for possible Bleichenbacher-style timing attack",
not "Fix the exploitable Marvin attack of such-and-such magnitude".

# marvin-toolkit
A set of tools and instructions to check if a library is vulnerable to the Marvin attack.

Marvin attack is a continuation of work published by Hanno Böck, Juraj
Somorovsky, and Craig Young in their ROBOT Attack[[1]](https://robotattack.org/).

Version: 0.1

Primary contact: Hubert Kario (hkario@redhat.com)

## The vulnerability

Marvin is the extension of the same vulnerability described by Daniel
Bleichenbacher in 1998[[2]](https://link.springer.com/content/pdf/10.1007%2FBFb0055716.pdf)
with the difference being that the used oracle doesn't use the TLS or SSL
alerts to differentiate ciphertexts but rather the time it takes the server
or system under test to process the message.

Use of non-constant time code, differences in memory accesses, explicit error
handling, etc. All those things impact the time it takes the system under test
to process a ciphertext.
That means that both the library providing the API needs to process the
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

If an attacker can measure precisely the decryption time of the RSA ciphertext
of their choosing, we've shown decryption of ciphertexts possible in as
little as 20 minutes.

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

As an application programmer: stop using RSA encryption.
If you're library vendor stop providing RSA PKCS#1 v1.5 decryption support.
If possible, don't provide RSA OAEP decryption support either—while depadding
is much easier to perform in side-channel free way, it depends on the previous
RSA decryption step being constant time.
That is, security of RSA OAEP requires big integer arithmetic that is
constant time.
For example, gmplib does not provide high-level functions for side-channel
free deblinding (multiplication modulo) and OpenSSL BIGNUM doesn't
provide a consistent public interface to perform the de-blinding step and
conversion to a byte string in side-channel free manner.

If deprecation and later removal of the decryption support is not possible,
document the API as known vulnerable.
The users of such an API should be inspected to check if the timing signal
is likely to leak to other processes, VMs or over the network.
The last option being the most severe.
Such applications will need to be fixed then.

In case users of the API know a priori what's the expected size of the
decrypted secret, providing an API that generates a random secret of that size
and returns it in case of errors in padding, instead of the decrypted value,
is the recommended way to workaround this vulnerability. See the TLS 1.2 RFC
5246 page 58 for details.

## Are signatures vulnerable?

To the best of our knowledge APIs for performing RSA signatures,
both RSA-PSS and RSA PKCS#1 v1.5, are not affected.
Though please note that this assumes that the RSA implementation uses blinding
correctly when computing the signature.

That being said, all Bleichenbacher-style attacks can be used to create an
arbitrary signature using the key exposed through the vulnerable decryption
oracle.

## How to test?

To test a library or application you need to time how long the API call takes
to process specific ciphertexts.
You need to test the decryption times repeatedly to collect enough data
for statistically significant result.
The longer the library takes to process the message with the ciphertext
and the smaller the difference between different ciphertexts, the
more observations are necessary to show that a library is vulnerable.
In practice, for a local library call, with nanosecond precision timers,
a collection of 100k to a 1M calls per ciphertext are sufficient to
conclusively prove a volnerability.
For a fast library, collection of 10M calls may be enough to show that
if the side channel exists, it's smaller than a single CPU cycle.
For a slow one it make take 1B calls or more.
As a rule of thumb start with 100k and then increase by an order of magnitude
until tests show too small timing side channel to be possible.
Once you've collected enough data you need to perform statistical tests
to check for presence of the side-channel.

For a programmer familiar with the decryption API and access to a modern
Linux system we don't expect the preparation to take more than an hour.
Execution of the tests may take multiple hours or days of machine time.

This toolkit provides 3 tools:

1. Script to generate the RSA keys
2. Script to generate the RSA ciphertexts with known plaintext structure
3. Script to analyse the collected results

They have been created with a tests running against a local API in mind.
For a script testing the RSA key exchange in TLS see the
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html).

### Preparation

The scripts here require modern version of Python (at least 3.7), but they
don't have to be executed on the same machine that executes the timing tests.

To create the virtual environment and install the dependencies run the
`step0.sh` script.

This script will create a python virtual environment in `marvin-venv`
directory and install all the necessary dependencies for the scripts
to generate ciphertexts and analyse results.

It will also create two more directories: `certgen` a bash library for
generation of certificates and `tlsfuzzer` where the analysis script lives.

It's safe to re-run the script, while it creates those directories it
will not overwrite them or their contents. That also means, if you need to
use newer version of tlsfuzzer, you will need to either update that
git repo checkout or delete the directory and re run the script.

### Generating the certificates

You can generate the certificates using the `step1.sh` script.
It will create three directories: `rsa1024`, `rsa2048` and `rsa4096` with the
key in 3 different formats: old OpenSSL, PKCS#8 and PKCS#12 (the password for
PKCS#12 file is empty). Use whichever is easiest to work with with your
application.
It also generates self signed certificates signed with those keys, in case
the key store requires associating a key with certificate for use.

You need to pass the certificates to the script generating the ciphertexts.

There is nothing special about those keys, the script is provided only for
convinience.

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
`M` is the message for encryption, provided by user to the library.

The first byte (0x00) is also called the version byte (though PKCS#1 v2.0
didn't change it).
The second byte (0x02) specifies the padding type, for signatures it's
0x01 and the PS is a repeated 0xff byte. It can also be 0x00 to specify
no padding, but then first byte of message must be non-zero.
Padding bytes don't include bytes of size zero.

The miminal size of PS is also specified at 8 bytes.

Thus, a compliant implementation needs to:

1. Perform RSA decryption, convert the integer into a string of bytes
2. Check if first byte is 0
3. Check if second bytes is 2
4. Look for the zero byte separating padding string from message
5. Check if the length of padding string is at least 8 bytes
6. (Protocol specific) Check if the message has expected length
7. (Protocol specific) Check if the message has specific structure
8. (Protocol specific) In case any tests failed, use the previously generated
   random message of expected length

All those steps must be performed using side-channel free code.

Different ciphertexts exercise different steps of the above list,
some exercise multiple.

#### Selecting ciphertexts

Step 1 will be mostly likely influenced by either the bit length of the
decrypted value or the
[Hamming weight](https://en.wikipedia.org/wiki/Hamming_weight) of the decrypted
value—provided that correct blinding is used.

##### Plaintext bit size

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
Use small message sizes (<= 48) for the `no_padding` for strongest signal.

##### Plaintext Hamming weight

Ciphertexts that generate plaintext with high Hamming weight are:

* `signature_padding` for message size small relative to key size (<= 48 bytes
  as a rule of thumb)
* `valid_repeated_byte_payload` for long message sizes (>= key size/2) and
  a message byte with high hamming weight (0xff, 0x7f, 0xbf, etc.)

Ciphertexts that generate plaintext with low Hamming weight are:

* `no_padding` for small message sizes (<= key size/2)
* `too_short_paylod` for large padding substractions (>= key size/2)
* `valid_repeated_byte_payload` for long message sizes (>= key size/2) and
  a message byte with low hamming weight (0x00, 0x01, 0x02, etc.)

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
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`, for zero padding substraction

There are two special values for the type byte, 0x01 and 0x02, so
it's good idea to test `valid` for the positive case and both `no_structure`
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
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`

Which ciphertexts are interesting is highly dependent on the specific
implementation. The `no_structure` and `header_only` are generally the best
for negative test case, but for positive tests generally the `valid` and
`no_header_with_payload` are most likely to show interesting timing signal.

##### Padding length check

For padding length check the implementation can use two algorithms:

1. look for first non zero byte, consider it a padding type, look for next
   zero byte (this is incorrect)
2. Decrypt the ciphertext, and look at bytes 3 to 10 (inclusive) of plaintext,
   verify that all of them are non-zero (this is the correct approach)

So below are two sets of ciphertexts, first pair for the first type of
implementation and the second par for a second type.

Ciphertexts that produce plaintext with padding of correct length
(that is, a search for a zero in padding will be successful and its
length will be longer than 8 bytes):

* `no_header_with_payload`, for messages shorter than key_size - 10
* `version_with_padding`, for messages shorter than key_size - 10
* `type_with_padding`, for messages shorter than key_size - 10
* `signature_type`, for messages shorter than key_size - 10
* `signature_padding`, for messages shorter than key_size - 10
* `valid`, for messages shorter than key_size - 10
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
* `zero_byte_in_padding`, for messages lenger than key_size - 10 and for
  zero_byte positions lower or equal to 8
* `valid_repeated_byte_payload`, for messages shorter than key_size - 10
* `too_short_payload`, for messages longer than key_size - 10 - padding_sub

For second type implementation, the ciphertexts that will have no zero bytes
at any of the bytes between 3 and 10 (inclusive):

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
* `zero_byte_in_padding`, for messages shorter than key_size - 10 and
  zero_byte position higher than 8
* `valid_repeated_byte_payload`, for messages shorter than key_size - 10
* `too_short_payload`, for messages shorter than key_size - 10 and padding
  substraction equal 0 or 1

Here, the two probes that are most likely to give consistent results are the
`zero_byte_in_padding` with a reasonable messege length (<= 48 bytes) and
zero_byte position between 0 and 8 inclusive. For positive test use
`valid` with a message of same length.

##### Message length check

For checking if the library correctly tests the length of the message, or
if the length of the message doesn't provide a side channel use
one of the probes that allow setting length of the message:

* `no_header_with_payload`
* `version_with_padding`
* `type_with_padding`
* `signature_type`
* `signature_padding`
* `no_padding`
* `valid`
* `zero_byte_in_padding`
* `valid_repeated_byte_payload`
* `too_short_payload`

The probe that is least likely to provide false signal is the `valid` one.
You should test different lengths, from 0 (including 0) up to the max size
supported by the key (key_length - 10), and at least few in between: typical
sizes for symmetric key sizes: 16, 24, 32, 48, some that may cause buffer
overflow: 1, 2, 4, as well as 128, 192, 256 (if supported by given key size).
See also CVE-2012-5081.

##### Custom structure

In case the protocol requires specific structure of the encrypted message
we can only suggest modifying the `step2.py` script to generate random
messages that follow it.

For TLS, which requires two first bytes of the message to equal the negotiated
version you should use the
[test-bleichenbacher-timing.py](https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-bleichenbacher-timing.py) script in tlsfuzzer.
See [tlsfuzzer documenation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
for instructions how to execute it.

##### Summary

Given the above notes, we suggest running the following set of probes to
look for side channels in an implementation:

* `no_structure`
* `no_padding` with message length 48
* `signature_padding` with message length 0
* `valid_repeated_byte_payload` with message 3 bytes shorter than key and
  0x00 as message byte
* `valid` with message length 48
* `header_only`
* `no_header_with_payload` with message length 48
* `zero_byte_in_padding` with message length 48 and zero_byte of 4
* `valid` with message length 0, 192, and key_length - 10
* Optionally: also `valid` with message length 1, 2, 16, 32, and, 128

In case the protocol you're testing requires specific message length, change
the length from 48 to the required length and add the 48 to the last set of
probes.

Use the following commands to generate them for the previously generated keys:
```
./marvin-venv/bin/python ./step2.py -c rsa1024/cert.pem -o rsa1024_ciphertexts \
no_structure no_padding=48 signature_padding=0 \
valid_repeated_byte_payload="125 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=118
./marvin-venv/bin/python ./step2.py -c rsa2048/cert.pem -o rsa2048_ciphertexts \
no_structure no_padding=48 signature_padding=0 \
valid_repeated_byte_payload="253 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=192 valid=246
./marvin-venv/bin/python ./step2.py -c rsa4096/cert.pem -o rsa4096_ciphertexts \
no_structure no_padding=48 signature_padding=0 \
valid_repeated_byte_payload="509 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=192 valid=502
```

You'll find the ciphertexts in the `rsa1024_ciphertexts`,
`rsa2048_ciphertexts`, and `rsa4096_ciphertexts` directories.

Use other probes or other parameters when you find a timing signal and want
to pin-point the likely incorrectly implemented check.

For testing OAEP interface you should use the following ciphertexts:

* `no_structure`
* `valid` (any length)
* `no_padding` with short message size (<= 48 bytes)
* `signature_padding` with message length 0
* `valid_repeated_byte_payload` with message 3 bytes shorter than key and
  0x00 as message byte

### Writing the test harness

<!-- execute in tuples, in random order, write results to a csv with
samples in columns -->

### Running the test

<!-- suggest following tlsfuzzer setup for the machine if the necessary
sample size is large -->

### Analysing the results

<!-- provide examples of clearly exploitable implementations and
vulnerable implementations, explain what to look for -->
