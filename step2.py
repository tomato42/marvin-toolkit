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

    def __init__(self, public_key):
        self.pub_key = public_key
        self.key_size = divceil(len(public_key), 8)

    def encrypt_plaintext(self, plaintext):
        """
        Performs raw RSA encryption on plaintext
        """
        assert len(plaintext) == self.key_size, \
            "Plaintext length ({0}) doesn't match key length ({1})".format(
                    len(plaintext), self.key_size)
        msg = self.pub_key._rawPublicKeyOp(int.from_bytes(plaintext, "big"))
        return int(msg).to_bytes(self.key_size, "big")

    types["no_structure"] = 0

    def no_structure(self):
        """
        Create a plaintext that can't be mistaken for PKCS#1 v1.5 padding.
        Has incorrect header and no separator between PS and M.

        Makes sure to also not suggest a PKCS#1 v1.5 signature padding.
        """
        plaintext = [random.choice(range(1, 128)),
                     random.choice(range(3, 256))] + \
                    random.choices(range(1, 256), k=self.key_size-2)
        return self.encrypt_plaintext(plaintext)

    types["no_structure_with_chosen_plaintext"] = 1
    
    def no_structure_with_chosen_plaintext(self, chosen_plaintext):
        """
        Create a plaintext that can't be mistaken for PKCS#1 v1.5 padding.
        Has incorrect header and no separator between PS and M.

        Makes sure to also not suggest a PKCS#1 v1.5 signature padding.
        
        arguments:
          - chosen_plaintext: a int array of bytes for both the start of the file and his content. Bytes must be of number between 0 and 255
        """
        
        plaintext = chosen_plaintext  + \
                    random.choices(range(1, 256), k=self.key_size-2)
                    
        return self.encrypt_plaintext(plaintext)

    types["no_header_with_payload"] = 1

    def no_header_with_payload(self, m_length):
        """
        Creates a plaintext that has incorrect header (doesn't start with
        0x00 0x02) but has padding separator
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [random.choice(range(1, 128)),
                     random.choice(range(3, 256))] + \
                    random.choices(range(1, 256),
                                   k=self.key_size-2-1-m_length) + \
                    [0] + \
                    random.choices(range(0, 256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["version_only"] = 0

    def version_only(self):
        """
        Creates a PKCS#1 v1.5 plaintext with only the first byte correct
        (0x00), incorrect padding type (neither 0, 1 or 2) and no
        null separator between PS (padding) and M (payload).
        """
        plaintext = [0, random.choice(range(3, 256))] + \
            random.choices(range(1, 256), k=self.key_size-2)
        return self.encrypt_plaintext(plaintext)

    types["version_with_padding"] = 1

    def version_with_padding(self, m_length):
        """
        Creates a PKCS#1 v1.5 plaintext with the first byte correct
        (0x00), incorrect padding type (neither 0, 1 or 2) and a
        null separator between PS (padding) and M (payload) with
        random payload of specified length.
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [0, random.choice(range(3, 256))] + \
            random.choices(range(1, 256), k=self.key_size-2-1-m_length) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["type_only"] = 0

    def type_only(self):
        """
        Creates a PKCS#1 v1.5 plaintext with incorrect first byte (non zero).
        correct second byte (0x02), and no
        null separator between PS (padding) and M (payload).
        """
        plaintext = [random.choice(range(1, 128)), 2] + \
            random.choices(range(1, 256), k=self.key_size-2)
        return self.encrypt_plaintext(plaintext)

    types["type_with_padding"] = 1

    def type_with_padding(self, m_length):
        """
        Creates a PKCS#1 v1.5 plaintext with incorrect first byte (not 0x00),
        correct padding type (0x02) and a
        null separator between PS (padding) and M (payload) with
        random payload of specified length.
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [random.choice(range(1, 128)), 2] + \
            random.choices(range(1, 256), k=self.key_size-2-1-m_length) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["signature_type"] = 1

    def signature_type(self, m_length):
        """
        Creates a PKCS#1 v1.5 plaintext with correct first byte (0x00),
        incorrect type byte (0x01 - used for signature padding) and a
        random paylod of specified length.
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [0, 1] + \
            random.choices(range(1, 256), k=self.key_size-2-1-m_length) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["signature_padding"] = 1

    def signature_padding(self, m_length):
        """
        Creates a PKCS#1 v1.5 plaintext with correct first byte (0x00),
        incorrect type byte (0x01 - used for signature padding), padding
        typical for signatures (0xFF bytes) and random payload of specified
        length.
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [0, 1] + \
            [0xff] * (self.key_size-2-1-m_length) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["no_padding"] = 1

    def no_padding(self, m_length):
        """
        Creates a PKCS#1 v1.5 plaintext with no padding (starts with 0x00,
        0x00), and all padding bytes are 0x00, with the random payload of
        specified length.
        This is the simple, textbook, version of RSA.
        """
        if m_length > self.key_size:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size))
        if m_length < 1:
            raise ValueError("Message must be at least 1 byte long")
        plaintext = [0] * (self.key_size - m_length) + \
            [random.choice(range(1, 256))] + \
            random.choices(range(256), k=m_length-1)
        return self.encrypt_plaintext(plaintext)

    types["header_only"] = 0

    def header_only(self):
        """
        Creates PKCS#1 v1.5 plaintext with just the correct two byte header
        0x00 0x02, without the null separator between PS and M.
        """
        plaintext = [0, 2] + random.choices(range(1, 256), k=self.key_size-2)
        return self.encrypt_plaintext(plaintext)

    types["valid"] = 1

    def valid(self, m_length):
        """
        Create a random, valid PKCS#1 v1.5 plaintext with payload
        of specified length.

        Doesn't check if the message size will allow
        for the minimum of 8 byte padding!
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [0, 2] + \
            random.choices(range(1, 256), k=self.key_size-2-1-m_length) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["valid_version"] = 3

    def valid_version(self, m_length, first, second):
        """
        Create a random, valid PKCS#1 v1.5 plaintext with payload
        of specified length that starts with the two specified bytes.

        Useful for creating TLS-conforming PKCS#1v1.5 ciphertexts.

        Doesn't check if the message size will allow
        for the minimum of 8 byte padding!
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        plaintext = [0, 2] + \
            random.choices(range(1, 256), k=self.key_size-2-1-m_length) + \
            [0, first, second] + random.choices(range(256), k=(m_length-2))
        return self.encrypt_plaintext(plaintext)

    types["zero_byte_in_padding"] = 2

    def zero_byte_in_padding(self, m_length, zero_byte):
        """
        Create a random PKCS#1 v1.5 plaintext with payload
        of specified length and a single zero byte in padding.
        Useful for testing implementations expecting message of specific size.
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        ps_len = self.key_size-2-1-m_length
        first_ps_len = zero_byte
        second_ps_len = ps_len - zero_byte - 1
        if second_ps_len < 0:
            raise ValueError("Zero byte too far for key size, max pos: {0}"
                .format(ps_len-1))
        plaintext = [0, 2] + \
            random.choices(range(1, 256), k=first_ps_len) + \
            [0] + random.choices(range(1, 256), k=second_ps_len) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)

    types["valid_repeated_byte_payload"] = 2

    def valid_repeated_byte_payload(self, m_length, payload_byte):
        """
        Create a random, valid PKCS#1 v1.5 plaintext with payload of
        specified length and all payload bytes set to the specific value.

        If the payload size won't allow for 8 bytes of padding string,
        the created message will be invalid.
        """
        if m_length > self.key_size - 3:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3))
        if payload_byte not in range(256):
            raise ValueError("Bytes can have only values between 0 and 255")
        plaintext = [0, 2] + \
            random.choices(range(1, 256), k=self.key_size-2-1-m_length) + \
            [0] + [payload_byte] * m_length
        return self.encrypt_plaintext(plaintext)

    types["too_short_payload"] = 2

    def too_short_payload(self, m_length, padding_sub):
        """
        Sends a valid-like PKCS#v 1.5 padding: one that starts with too many
        zero bytes.
        Second parameter specifies how much shorter the padding should be.
        So to send a padding valid for 1024 bit key with 2048 bit key specify
        128 (bytes) as the second parameter.
        """
        if padding_sub > self.key_size - 3:
            raise ValueError("Too big padding substraction, max: {0}".format(
                self.key_size - 3))
        if m_length > self.key_size - 3 - padding_sub:
            raise ValueError("Too big message size, max size: {0}".format(
                self.key_size - 3 - padding_sub))
        plaintext = [0] * padding_sub + [0, 2] + \
            random.choices(range(1, 256),
                k=self.key_size-2-1-m_length-padding_sub) + \
            [0] + random.choices(range(256), k=m_length)
        return self.encrypt_plaintext(plaintext)


def help_msg():
    print(
"""
{0} -c cert.pem [-o dir] ciphertext_name[="param1 param2"] [ciphertext_name]

Generate ciphertexts for testing RSA decryption interface against
timing side-channel.

-c cert.pem      Path to PEM-encoded X.509 certificate
-o dir           Directory that will contain the generated ciphertexts.
                 "ciphertexts" by default.
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


def single_shot(out_dir, pub, args):
    generator = CiphertextGenerator(pub)

    for arg in args:
        ret = arg.split('=')
        
        print(arg)
        print(ret)
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


        print(name)
        print(params)
        ciphertext = getattr(generator, name)(*params)

        file_name = "_".join([name] + [str(i) for i in params])

        with open(os.path.join(out_dir, file_name), "wb") as out_file:
            out_file.write(ciphertext)


def gen_timing_probes(out_dir, pub, args, repeat, verbose=False):
    generator = CiphertextGenerator(pub)

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

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "c:o:", ["help", "describe=", "repeat=",
                                              "force", "verbose"])
    for opt, arg in opts:
        if opt == "-c":
            cert = arg
        elif opt == "-o":
            out_dir = arg
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
        single_shot(out_dir, pub, args)
    else:
        gen_timing_probes(out_dir, pub, args, repeat, verbose)
