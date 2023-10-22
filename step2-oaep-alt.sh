#!/bin/bash

PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa1024/cert.pem -o rsa1024_oaep_repeat \
--repeat 100000 --verbose \
no_structure valid=0 \
too_short_payload="0 1" too_short_payload="0 3" too_short_payload="0 7" \
too_short_payload="0 15" \
no_padding=48 signature_padding=0 \
valid_repeated_byte_payload="117 0x00"

PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa2048/cert.pem -o rsa2048_oaep_repeat \
--repeat 100000 --verbose \
no_structure valid=0 \
too_short_payload="0 1" too_short_payload="0 3" too_short_payload="0 7" \
too_short_payload="0 15" \
no_padding=48 signature_padding=0 \
valid_repeated_byte_payload="245 0x00"

PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa4096/cert.pem -o rsa4096_oaep_repeat \
--repeat 100000 --verbose \
no_structure valid=0 \
too_short_payload="0 1" too_short_payload="0 3" too_short_payload="0 7" \
too_short_payload="0 15" \
no_padding=48 signature_padding=0 \
valid_repeated_byte_payload="501 0x00"
