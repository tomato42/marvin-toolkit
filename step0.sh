#!/bin/bash

if ! [[ -x `which git` ]]; then
    echo "Error: Git is necessary to execute the script" >&2
    exit 1
fi

if ! [[ -x `which openssl` ]]; then
    echo "Error: OpenSSL command line utility is necessary for this script" >&2
    exit 1
fi

if ! [[ -x $PYTHONBIN ]]; then
    PYTHONBIN=`which python3`
fi

if $PYTHONBIN -c "import sys;sys.exit(sys.version_info >= (3, 7))"; then
    echo "Error: python executable too old, define PYTHONBIN variable that points to version 3.7 or later" >&2
    exit 1
fi

if ! [[ -d marvin-venv ]]; then
    $PYTHONBIN -m venv marvin-venv
fi

if ! [[ -d tlsfuzzer ]]; then
    git clone --depth=1 https://github.com/tomato42/tlsfuzzer.git
else
    echo "Info: tlsfuzzer detected, not upgrading"
fi

pushd tlsfuzzer
../marvin-venv/bin/pip install -r requirements.txt -r requirements-timing.txt
popd

if ! [[ -d certgen ]]; then
    git clone --depth=1 https://github.com/redhat-qe-security/certgen.git
else
    echo "Info: certgen detected, not upgrading"
fi
