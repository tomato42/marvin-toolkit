#!/bin/python
import sys
from tlslite.utils.python_rsakey import Python_RSAKey
from tlslite.utils.compat import b2a_hex, int_to_bytes


if len(sys.argv) != 3:
    print("usage: {0} key.pem out.txt")
    sys.exit(1)


with open(sys.argv[1], "r") as f:
    key = Python_RSAKey.parsePEM(f.read())

with open(sys.argv[2], "w") as f:
    f.write("n=")
    f.write(b2a_hex(int_to_bytes(key.n)))
    f.write("\n")

    f.write("e=")
    f.write(b2a_hex(int_to_bytes(key.e)))
    f.write("\n")

    f.write("d=")
    f.write(b2a_hex(int_to_bytes(key.d)))
    f.write("\n")

    f.write("p=")
    f.write(b2a_hex(int_to_bytes(key.p)))
    f.write("\n")

    f.write("q=")
    f.write(b2a_hex(int_to_bytes(key.q)))
    f.write("\n")

    f.write("qInv=")
    f.write(b2a_hex(int_to_bytes(key.qInv)))
    f.write("\n")
