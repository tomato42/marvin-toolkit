#!/bin/bash

PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa1024/cert.pem -o rsa1024_ciphertexts \
no_structure no_padding=48 signature_padding=8 \
no_structure_with_chosen_plaintext="1 2 3" \
valid_repeated_byte_payload="118 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=118

PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa2048/cert.pem -o rsa2048_ciphertexts \
no_structure no_padding=48 signature_padding=8 \
no_structure_with_chosen_plaintext="1 2 3" \
valid_repeated_byte_payload="246 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=192 valid=246

PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
-c rsa4096/cert.pem -o rsa4096_ciphertexts \
no_structure no_padding=48 signature_padding=8 \
no_structure_with_chosen_plaintext="1 2 3" \
valid_repeated_byte_payload="502 0xff" valid=48 header_only \
no_header_with_payload=48 zero_byte_in_padding="48 4" \
valid=0 valid=192 valid=502
