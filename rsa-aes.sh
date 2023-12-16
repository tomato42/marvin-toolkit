#!/bin/bash

PYTHONPATH=tlsfuzzer/ \
marvin-venv/bin/python ./rsa-aes-gen.py \
-o rsa1024aes128_repeat/ \
-l 256 --tag example --repeat 10000 -c rsa1024/cert.pem \
--verbose \
good_rsa_static_key_static_iv_good_pad_tag_present="1 0 0" \
good_rsa_static_key_static_iv_good_pad_tag_absent="1 0 0" \
good_rsa_static_key_good_pad_tag_present="12 0xff" \
good_rsa_static_key_good_pad_tag_absent="12 0xff" \
good_rsa_good_pad_tag_present="1" \
good_rsa_good_pad_tag_present="16" \
good_rsa_good_pad_tag_absent="1" \
good_rsa_good_pad_tag_absent="16" \
good_rsa_bad_pad_tag_present="2 -2" \
good_rsa_bad_pad_tag_present="16 -2" \
good_rsa_bad_pad_tag_present="16 -16" \
good_rsa_bad_pad_tag_absent="2 -2" \
good_rsa_random_pad_tag_present \
good_rsa_random_pad_tag_absent \
wrong_size_rsa_random_aes=15 \
wrong_size_rsa_random_aes=17 \
wrong_size_rsa_random_aes=0 \
wrong_size_rsa_random_aes=32 \
bad_rsa_random_aes
