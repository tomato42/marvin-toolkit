#!/bin/bash

if [[ -e rsa1024_repeat ]]; then
    echo "directory rsa1024_repeat exists!"
    exit 1
fi

mkdir rsa1024_repeat
PYTHONPATH=tlsfuzzer/ marvin-venv/bin/python \
tlsfuzzer/scripts/marvin-ciphertext-generator.py \
-o rsa1024_repeat --repeat 1000 \
--srv-key rsa1024/key.pem --srv-cert rsa1024/cert.pem

if [[ -e rsa2048_repeat ]]; then
    echo "directory rsa2048_repeat exists!"
    exit 1
fi

mkdir rsa2048_repeat
PYTHONPATH=tlsfuzzer/ marvin-venv/bin/python \
tlsfuzzer/scripts/marvin-ciphertext-generator.py \
-o rsa2048_repeat --repeat 1000 \
--srv-key rsa2048/key.pem --srv-cert rsa2048/cert.pem

if [[ -e rsa4096_repeat ]]; then
    echo "directory rsa4096_repeat exists!"
    exit 1
fi

mkdir rsa4096_repeat
PYTHONPATH=tlsfuzzer/ marvin-venv/bin/python \
tlsfuzzer/scripts/marvin-ciphertext-generator.py \
-o rsa4096_repeat --repeat 1000 \
--srv-key rsa4096/key.pem --srv-cert rsa4096/cert.pem
