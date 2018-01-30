#!/bin/sh

set -e

BINARY_SAMPLES_GITHUB="https://github.com/JonathanSalwan/binary-samples.git"
CAPSTONE_GITHUB="https://github.com/aquynh/capstone"


if test ! -d capstone
then
    git clone $CAPSTONE_GITHUB capstone
fi

cd capstone
git pull
./make.sh
cd ..

# Download test suite binaries
if test ! -d binary-samples
then
    git clone $BINARY_SAMPLES_GITHUB binary-samples
else
    cd binary-samples
    git pull
    cd ..
fi
