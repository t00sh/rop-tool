#!/bin/sh

if test -z $1
then
    echo "Usage : $0 <version>"
    exit 1
fi

rm *.asc

OLD_VERSION=$(sed -rn "s/^VERSION = (.*)/\1/p" Makefile.inc)
NEW_VERSION=$1

sed -i -r "s/VERSION = .+/VERSION = $NEW_VERSION/g" Makefile.inc

git tag v$NEW_VERSION

# Linux
ARCH=x86 make -f Makefile clean
ARCH=x86 make -f Makefile release

ARCH=x86-64 make -f Makefile clean
ARCH=x86-64 make -f Makefile release

# Windows
ARCH=x86 make -f Makefile.windows clean
ARCH=x86 make -f Makefile.windows release

ARCH=x86-64 make -f Makefile.windows clean
ARCH=x86-64 make -f Makefile.windows release


rsync -Pravdtze ssh rop-tool* www-data@t0x0sh.org:~/t0x0sh/rop-tool/releases/$NEW_VERSION/
