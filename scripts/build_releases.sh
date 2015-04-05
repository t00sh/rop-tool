#!/bin/sh

# How to release :
# - Modify CHANGES file
# - Modify README.md
# - Commit on dev branch
# - Run this script

if test ! -z $1
then
    ONLY_BUILD=1
fi

rm *.asc

if test ! -z $ONLY_BUILD
then
    OLD_VERSION=$(sed -rn "s/^VERSION = (.*)/\1/p" Makefile.inc)
    NEW_VERSION=$1
    
    sed -i -r "s/VERSION = .+/VERSION = $NEW_VERSION/g" Makefile.inc
    
    git tag v$NEW_VERSION
    git checkout master
    git merge dev
    git push --tags
    git push
fi


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


if test -z ! $ONLY_BUILD
then
    rsync -Pravdtze ssh rop-tool* www-data@t0x0sh.org:~/t0x0sh/rop-tool/releases/$NEW_VERSION/
fi
