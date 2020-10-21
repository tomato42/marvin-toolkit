# marvin-toolkit
A set of tools and instructions to check if a library is vulnerable to the Marvin attack.

Marvin attack is a continuation of work published by Hanno Böck, Juraj
Somorovsky, and Craig Young in their ROBOT Attack[[1]](https://robotattack.org/).

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

As it's not the typical requirement for written code, especially outside of
cryptographic libraries, it's likely that even if it was written to
side-channel free standard, it wasn't tested for at least constant-timeness.

This is where this toolkit comes in.

## How bad it is?

If an attacker can measure precisely the decryption time of the RSA ciphertext
of their choosing, we've shown decryption of ciphertexts in as little as 20
minutes as possible.

That may be usable for TLS session decryption, e-mail decryption or
forging of signatures.

## Who is affected?

Any application that uses RSA decryption may be vulnerable.
Protocols that use RSA PKCS#1 v1.5 encryption padding are especially
vulnerable.
RSA OEAP defined in PKCS#1 v2.0 can also be implemented in a way that
leaks enough information to mount a timing attack.

## What's the recommended solution?

Stop providing RSA PKCS#1 v1.5 decryption support. If possible, don't
provide RSA OEAP decryption support either—while depadding is much easier
to perform in side-channel free way, it depends on the previous RSA
decryption step being constant time.
That is, security of RSA OEAP requires big integer arithmetic that is
constant time.
For example, gmplib does not provide high-level functions for side-channel
free deblinding (multiplication modulo) while and OpenSSL BIGNUM doesn't
provide a public interface to perform the de-blinding step and conversion to
a byte string in side-channel free manner.

If deprecation and later removal of the decryption support is not possible,
document the API as known vulnerable.
The users of such an API should be inspected to check if the timing signal
is likely to leak to other processes, VMs or over the network.
The last option being the most severe.

In case users of the API know a priori what's the expected size of the
decrypted secret, providing an API that generates a random secret of that size
and returns it in case of errors in padding is the recommended way to
workaround this vulnerability. See the TLS 1.2 RFC 5246 page 58 for details.

## Are signatures vulnerable?

To the best of our knowledge APIs for performing RSA signatures,
both RSA-PSS and RSA PKCS#1 v1.5, are not affected.
Though please note that this assumes that the RSA implementation uses blinding.

That being said, all Bleichenbacher attacks can be used to create an arbitrary
signature using the key exposed through vulnerable encryption API.

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

This toolkit provides 3 tools:

1. Script to generate the RSA keys
2. Script to generate the RSA ciphertexts with known plaintext structure
3. Script to analyse the collected results

They have been created with a tests running against a local API in mind.
For a script testing the RSA key exchange in TLS see
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html).

### Preparation

The scripts here require modern version of Python (at least 3.8), but they
don't have to be executed on the same machine that executes the timing tests.

To create the virtual environment and install the dependencies run the
`step0.sh` script.

This script will create a python virtual environment in `marvin-venv`
directory and install all the necessary dependencies for the scripts
to generate ciphertexts and analyse results.

It will also create two more directories: `certgen` a bash library for
generation of certificates and `tlsfuzzer` where the analysis script lives.

It's safe to re-run the script, while it will create those directories it
will not overwrite them.

### Generating the ciphertexts

<!-- what kind of ciphertexts to generate, which ones are useful for
detecting vulnerability and which ones are good for looking for where
the issues is comming from -->

### Writing the test harness

<!-- execute in tuples, in random order, write results to a csv with
samples in columns -->

### Running the test

<!-- suggest following tlsfuzzer setup for the machine if the necessary
sample size is large -->

### Analysing the results

<!-- provide examples of clearly exploitable implementations and
vulnerable implementations, explain what to look for -->
