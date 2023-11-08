import sys
import getopt
import time
from M2Crypto import RSA, BIO


def help_msg():
    print("""
timing.py -i file -o file -k file -n size

-i file      File with the ciphertexts to decrypt
-o file      File to write the timing data to
-k file      The private key to use for decryption
-n size      Size of individual ciphertexts for decryption
-h | --help  this message
""")


if __name__ == '__main__':
    in_file = None
    out_file = None
    key_file = None
    read_size = None

    argv = sys.argv[1:]
    if not argv:
        help_msg()
        sys.exit(1)
    opts, args = getopt.getopt(argv, "i:o:k:n:h", ["help"])

    for opt, arg in opts:
        if opt == "-h" or opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "-i":
            in_file = arg
        elif opt == "-o":
            out_file = arg
        elif opt == "-k":
            key_file = arg
        elif opt == "-n":
            read_size = int(arg)
        else:
            raise ValueError("Unrecognised parameter: {0} {1}"
                             .format(opt, arg))

    if not in_file:
        print("ERROR: no input file specified (-i)", file=sys.stderr)
        sys.exit(1)

    if not out_file:
        print("ERROR: no output file specified (-o)", file=sys.stderr)
        sys.exit(1)

    if not key_file:
        print("ERROR: no key file specified (-k)", file=sys.stderr)
        sys.exit(1)

    if not read_size:
        print("ERROR: size of ciphertexts unspecified (-n)", file=sys.stderr)
        sys.exit(1)

    with open(key_file, "rb") as key_fd:
        bio = BIO.MemoryBuffer(key_fd.read())
        priv_key = RSA.load_key_bio(bio)

    with open(in_file, "rb") as in_fd:
        with open(out_file, "w") as out_fd:
            out_fd.write("raw times\n")

            while True:
                ciphertext = in_fd.read(read_size)
                if not ciphertext:
                    break

                time_start = time.monotonic_ns()
                plaintext = priv_key.private_decrypt(
                        ciphertext,
                        RSA.pkcs1_padding)
                diff = time.monotonic_ns() - time_start

                out_fd.write("{0}\n".format(diff))

    print("done")
