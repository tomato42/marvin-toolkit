#!/usr/bin/python3

import sys
import random
import getopt
import os
from threading import Thread, Event
from tlslite.x509 import X509
from tlslite.utils.cryptomath import divceil
from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.progress_report import progress_report
from tlslite.utils.python_aes import Python_AES


if sys.version_info < (3, 7):
    print("This script is compatible with Python 3.7 and later only")
    sys.exit(1)


def get_key(cert_file):
    """
    Read an X.509 certificate, extract public key from it.
    """
    with open(cert_file, "r") as f:
        key_txt = f.read()

    x509 = X509().parse(key_txt)

    return x509.publicKey


class CiphertextGenerator(object):
    """
    Class for generating different kinds of RSA plaintexts
    """

    types = {}

    def __init__(self, public_key, aes_size, tag):
        self.pub_key = public_key
        self.key_size = divceil(len(public_key), 8)
        self.aes_size = aes_size
        self.aes_key_size = 16
        self.tag = tag

    def encrypt_plaintext(self, plaintext):
        """
        Performs raw RSA encryption on plaintext
        """
        assert len(plaintext) == self.key_size, \
            "Plaintext length ({0}) doesn't match key length ({1})".format(
                    len(plaintext), self.key_size)
        msg = self.pub_key._rawPublicKeyOp(int.from_bytes(plaintext, "big"))
        return int(msg).to_bytes(self.key_size, "big")

    types["good_rsa_static_key_static_iv_good_pad_tag_present"] = 3

    def good_rsa_static_key_static_iv_good_pad_tag_present(self, p_len, k_byte, iv_byte):
        """
        Create valid RSA ciphertext with correct key, of repeated k_byte bytes.
        Create valid AES ciphertext with specified padding length, iv of
        repeated iv_byte bytes and tag present.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        """
        aes_plaintext = random.randbytes(self.aes_size - len(self.tag) - p_len) +\
            self.tag + bytes([p_len] * p_len)
        assert len(aes_plaintext) == self.aes_size
        aes_key = bytes([k_byte] * self.aes_key_size)
        iv = bytes([iv_byte] * 16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_static_key_static_iv_good_pad_tag_absent"] = 3

    def good_rsa_static_key_static_iv_good_pad_tag_absent(self, p_len, k_byte, iv_byte):
        """
        Create valid RSA ciphertext with correct key, of repeated k_byte bytes.
        Create valid AES ciphertext with specified padding length, iv of
        repeated iv_byte bytes and tag absent.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        """
        aes_plaintext = random.randbytes(self.aes_size - p_len) +\
            bytes([p_len] * p_len)
        assert len(aes_plaintext) == self.aes_size
        aes_key = bytes([k_byte] * self.aes_key_size)
        iv = bytes([iv_byte] * 16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_static_key_good_pad_tag_present"] = 2

    def good_rsa_static_key_good_pad_tag_present(self, p_len, k_byte):
        """
        Create valid RSA ciphertext with correct key, of repeated k_byte bytes.
        Create valid AES ciphertext with specified padding length and tag
        present.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        """
        aes_plaintext = random.randbytes(self.aes_size - len(self.tag) - p_len) +\
            self.tag + bytes([p_len] * p_len)
        assert len(aes_plaintext) == self.aes_size
        aes_key = bytes([k_byte] * self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_static_key_good_pad_tag_absent"] = 2

    def good_rsa_static_key_good_pad_tag_absent(self, p_len, k_byte):
        """
        Create valid RSA ciphertext with correct key, of repeated k_byte bytes.
        Create valid AES ciphertext with specified padding length and tag
        absent.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        """
        aes_plaintext = random.randbytes(self.aes_size - p_len) +\
            bytes([p_len] * p_len)
        assert len(aes_plaintext) == self.aes_size
        aes_key = bytes([k_byte] * self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_good_pad_tag_present"] = 1

    def good_rsa_good_pad_tag_present(self, p_len):
        """
        Create valid RSA ciphertext with correct key size.
        Create valid AES ciphertext with specified padding length and
        tag present.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        """
        aes_plaintext = random.randbytes(self.aes_size - len(self.tag) - p_len) +\
            self.tag + bytes([p_len] * p_len)
        assert len(aes_plaintext) == self.aes_size
        aes_key = random.randbytes(self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_good_pad_tag_absent"] = 1

    def good_rsa_good_pad_tag_absent(self, p_len):
        """
        Create valid RSA ciphertext with correct key size.
        Create valid AES ciphertext with specified padding length and
        tag absent.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        """
        aes_plaintext = random.randbytes(self.aes_size - p_len) +\
            bytes([p_len] * p_len)
        assert len(aes_plaintext) == self.aes_size
        aes_key = random.randbytes(self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_bad_pad_tag_present"] = 2

    def good_rsa_bad_pad_tag_present(self, p_len, err_pos):
        """
        Create valid RSA ciphertext with correct key size.
        Create invalid AES ciphertext, with specified padding length
        (p_len) and an invalid padding byte at err_pos from the end
        (with last byte being identified as -1, second to last as -2, etc.).
        Tag is present.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        Error position must lie within pad.
        """
        if -err_pos - 1 > p_len or err_pos >= 0:
            raise ValueError("invalid error position")

        pad = bytearray([p_len] * p_len)
        pad[err_pos] = 0

        aes_plaintext = random.randbytes(self.aes_size - len(self.tag) - p_len) \
            + self.tag + pad
        assert len(aes_plaintext) == self.aes_size
        aes_key = random.randbytes(self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_bad_pad_tag_absent"] = 2

    def good_rsa_bad_pad_tag_absent(self, p_len, err_pos):
        """
        Create valid RSA ciphertext with correct key size.
        Create invalid AES ciphertext, with specified padding length
        (p_len) and an invalid padding byte at err_pos from the end
        (with last byte being identified as -1, second to last as -2, etc.).
        Tag is absent.

        Padding length must be between 1 and 16 (inclusive) to be valid.
        Error position must lie within pad.
        """
        if -err_pos - 1 > p_len or err_pos >= 0:
            raise ValueError("invalid error position")

        pad = bytearray([p_len] * p_len)
        pad[err_pos] = 0

        aes_plaintext = random.randbytes(self.aes_size - p_len) \
            + pad
        assert len(aes_plaintext) == self.aes_size
        aes_key = random.randbytes(self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_random_pad_tag_present"] = 0

    def good_rsa_random_pad_tag_present(self):
        """
        Create valid RSA ciphertext with correct key size.
        Create invalid AES ciphertext, with random padding.
        Tag is present (the tag is present at location specified by
        last byte of padding, but padding is inconsistent).
        """
        # one byte long pad can't be invalid, as then it wouldn't be
        # one byte long...
        pad_len = random.randint(2, 16)
        pad = bytearray(random.randbytes(pad_len - 1))
        pad += bytes([pad_len])
        if pad[-2] == pad[-1]:
            pad[-2] ^= 0xff

        aes_plaintext = random.randbytes(self.aes_size - len(self.tag) - pad_len) \
            + self.tag + pad
        assert len(aes_plaintext) == self.aes_size
        aes_key = random.randbytes(self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["good_rsa_random_pad_tag_absent"] = 0

    def good_rsa_random_pad_tag_absent(self):
        """
        Create valid RSA ciphertext with correct key size.
        Create invalid AES ciphertext, with random padding.
        Tag is absent.
        """
        aes_plaintext = random.randbytes(self.aes_size)
        assert len(aes_plaintext) == self.aes_size
        aes_key = random.randbytes(self.aes_key_size)
        iv = random.randbytes(16)
        aes_ciphertext = Python_AES(aes_key, 2, iv).encrypt(aes_plaintext)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + iv + aes_ciphertext

    types["wrong_size_rsa_random_aes"] = 1

    def wrong_size_rsa_random_aes(self, k_size):
        """
        Create valid RSA ciphertext, but with specified key size.
        Create random AES ciphertext.

        To be invalid the key size must be different than used AES size
        (16 for AES-128, 32 for AES-256).
        """
        aes_key = random.randbytes(k_size)

        # since it will be processed with random, unpredictable key,
        # the ciphertext will be effectively random anyway, so don't
        # waste time on encrypting anything
        aes_ciphertext = random.randbytes(self.aes_size + 16)

        rsa_ciphertext = self.pub_key.encrypt(aes_key)

        return rsa_ciphertext + aes_ciphertext

    types["bad_rsa_random_aes"] = 0

    def bad_rsa_random_aes(self):
        """
        Create RSA ciphertext with invalid padding.
        Create random AES ciphertext.

        Creates a RSA plaintext that has incorrect header (doesn't start with
        0x00 0x02) but has padding separator
        """
        rsa_plaintext = [random.choice(range(1, 128)),
                         random.choice(range(3, 256))] + \
                         random.choices(range(1, 256),
                                        k=self.key_size-2-1-self.aes_key_size) + \
                         [0] + \
                         random.choices(range(0, 256), k=self.aes_key_size)
        rsa_ciphertext = self.encrypt_plaintext(rsa_plaintext)

        aes_ciphertext = random.randbytes(self.aes_size + 16)

        return rsa_ciphertext + aes_ciphertext


def help_msg():
    print(
"""
{0} -c cert.pem [-o dir] ciphertext_name[="param1 param2"] [ciphertext_name]

Generate ciphertexts for testing combined RSA+AES-CBC decryption interface
against timing side-channel. Assumes use of implicit rejection through
generation of random AES key in case of PKCS#1 v1.5 padding error.

-c cert.pem      Path to PEM-encoded X.509 certificate
-o dir           Directory that will contain the generated ciphertexts.
                 "ciphertexts" by default.
-l num           Length of AES ciphertext to generate (in bytes)
--tag=name       Tag to place at the end of AES plaintext (utf-8 string)
--describe=name  Describe the specified probe
--repeat=num     Save the ciphertexts in random order in a single file
                 (ciphers.bin) in the specified directory together with a
                 file specifying the order (log.csv). Used for generating
                 input file for timing tests.
--force          Don't abort when the output dir exists
--verbose        Print status progress when generating repeated probes
--help           This message

Supported probes:
{1}
""".format(sys.argv[0], "\n".join("{0}, args: {1}".format(
    i, j) for i, j in CiphertextGenerator.types.items())))


def single_shot(out_dir, pub, args, aes_len, tag):
    generator = CiphertextGenerator(pub, aes_len, tag)

    for arg in args:
        ret = arg.split('=')
        if len(ret) == 1:
            name = ret[0]
            params = []
        elif len(ret) == 2:
            name, params = ret
            ret = params.split(' ')
            params = [int(i, 16) if i[:2] == '0x' else int(i) for i in ret]
        else:
            print("ERROR: Incorrect formatting of option: {0}".format(arg))

        if len(params) != generator.types[name]:
            print("ERROR: Incorrect number of parameters specified for probe "
                  "{0}, expected: {1}, got {2}".format(
                      name, generator.types[name], len(params)),
                  file=sys.stderr)
            sys.exit(1)

        ciphertext = getattr(generator, name)(*params)

        file_name = "_".join([name] + [str(i) for i in params])

        with open(os.path.join(out_dir, file_name), "wb") as out_file:
            out_file.write(ciphertext)


def gen_timing_probes(out_dir, pub, args, repeat, aes_len, tag, verbose=False):
    generator = CiphertextGenerator(pub, aes_len, tag)

    probes = {}
    probe_names = []

    # parse the parameters
    for arg in args:
        ret = arg.split('=')
        if len(ret) == 1:
            name = ret[0]
            params = []
        elif len(ret) == 2:
            name, params = ret
            ret = params.split(' ')
            params = [int(i, 16) if i[:2] == '0x' else int(i) for i in ret]
        else:
            print("ERROR: Incorrect formatting of option: {0}".format(arg))

        if len(params) != generator.types[name]:
            print("ERROR: Incorrect number of parameters specified for probe "
                  "{0}, expected: {1}, got {2}".format(
                      name, generator.types[name], len(params)),
                  file=sys.stderr)
            sys.exit(1)


        method = getattr(generator, name)

        probe_name = "_".join([name] + [str(i) for i in params])

        if probe_name in probes:
            print("ERROR: duplicate probe name and/or parameters: {0}, {1}"
                  .format(name, params))
            sys.exit(1)

        probes[probe_name] = (method, params)
        probe_names.append(probe_name)

    # create an order in which we will write the ciphertexts in
    log = Log(os.path.join(out_dir, "log.csv"))

    log.start_log(probes.keys())

    for _ in range(repeat):
        log.shuffle_new_run()

    log.write()

    # reset the log position
    log.read_log()

    try:
        # start progress reporting
        status = [0, len(probe_names) * repeat, Event()]
        if verbose:
            kwargs = {}
            kwargs['unit'] = ' ciphertext'
            kwargs['delay'] = 2
            progress = Thread(target=progress_report, args=(status,),
                              kwargs=kwargs)
            progress.start()

        with open(os.path.join(out_dir, "ciphers.bin"), "wb") as out:
            # start the ciphertext generation
            for executed, index in enumerate(log.iterate_log()):
                status[0] = executed

                p_name = probe_names[index]
                p_method, p_params = probes[p_name]

                ciphertext = p_method(*p_params)

                out.write(ciphertext)

    finally:
        if verbose:
            status[2].set()
            progress.join()
            print()

    print("done")


if __name__ == '__main__':
    cert = None
    out_dir = "ciphertexts"
    repeat = None
    force_dir = False
    verbose = False
    aes_len = None
    tag = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "c:o:l:", ["help", "describe=", "repeat=",
                                              "force", "verbose", "tag="])
    for opt, arg in opts:
        if opt == "-c":
            cert = arg
        elif opt == "-o":
            out_dir = arg
        elif opt == "-l":
            aes_len = int(arg)
        elif opt == "--tag":
            tag = bytes(arg, "utf-8")
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "--force":
            force_dir = True
        elif opt == "--repeat":
            repeat = int(arg)
        elif opt == "--verbose":
            verbose = True
        elif opt == "--describe":
            try:
                fun = getattr(CiphertextGenerator, arg)
            except Exception:
                help_msg()
                raise ValueError("No ciphertext named {0}".format(arg))
            print("{0}:".format(arg))
            print(fun.__doc__)
            sys.exit(0)
        else:
            raise ValueError("Unrecognised option: {0}".format(opt))

    if not args:
        print("ERROR: No ciphertexts specified", file=sys.stderr)
        sys.exit(1)

    if not cert:
        print("ERROR: No certificate specified", file=sys.stderr)
        sys.exit(1)

    if aes_len is None:
        print("ERROR: no AES ciphertext length specified", file=sys.stderr)
        sys.exit(1)

    if tag is None:
        print("ERROR: no tag to place in AES plaintext specified",
              file=sys.stderr)
        sys.exit(1)

    if aes_len % 16:
        print("WARNING: AES plaintext must by a multiple of AES block"
              "size (16 bytes)", file=sys.stderr)

    if repeat is not None and repeat <= 0:
        print("ERROR: repeat must be a positive integer", file=sys.stder)
        sys.exit(1)

    pub = get_key(cert)

    print("working with {0}bit key".format(len(pub)))
    print("Will save ciphertexts to {0}".format(out_dir))

    try:
        os.mkdir(out_dir)
    except FileExistsError:
        if force_dir:
            pass
        else:
            raise

    if repeat is None:
        single_shot(out_dir, pub, args, aes_len, tag)
    else:
        gen_timing_probes(out_dir, pub, args, repeat, aes_len, tag, verbose)
