#!/bin/sh

set -e

CAPSTONE_GITHUB="https://github.com/aquynh/capstone"
CAPSTONE_DOWNLOAD="www.capstone-engine.org/download"

rm -rf capstone*win*

if test ! -d capstone-linux32
then
    git clone $CAPSTONE_GITHUB capstone-linux32
fi

cd capstone-linux32
git pull
./make.sh nix32
cd ..

if test ! -d capstone-linux64
then
    git clone $CAPSTONE_GITHUB capstone-linux64
fi

cd capstone-linux64
git pull
./make.sh
cd ..

CAPSTONE_VERSION=$(sed -rn "s/^Version:\s(.*)/\1/p" ./capstone-linux32/capstone.pc)

CAPSTONE_WIN32="www.capstone-engine.org/download/$CAPSTONE_VERSION/capstone-$CAPSTONE_VERSION-win32.zip"
CAPSTONE_WIN64="www.capstone-engine.org/download/$CAPSTONE_VERSION/capstone-$CAPSTONE_VERSION-win64.zip"

CAPSTONE_WIN32_DIR="./capstone-$CAPSTONE_VERSION-win32"
CAPSTONE_WIN64_DIR="./capstone-$CAPSTONE_VERSION-win64"

wget "$CAPSTONE_DOWNLOAD/$CAPSTONE_VERSION/$CAPSTONE_WIN32_DIR.zip"
wget "$CAPSTONE_DOWNLOAD/$CAPSTONE_VERSION/$CAPSTONE_WIN64_DIR.zip"

unzip $CAPSTONE_WIN32_DIR.zip
unzip $CAPSTONE_WIN64_DIR.zip

rm $CAPSTONE_WIN32_DIR.zip $CAPSTONE_WIN64_DIR.zip
 
