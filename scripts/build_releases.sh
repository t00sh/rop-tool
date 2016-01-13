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

rm -f *.asc
rm -f rop-tool*
rm -f libheap*

if test ! -z $ONLY_BUILD
then
    OLD_VERSION=$(sed -rn "s/^VERSION = (.*)/\1/p" Makefile.inc)
    NEW_VERSION=$1

    sed -i -r "s/VERSION = .+/VERSION = $NEW_VERSION/g" Makefile.inc

    git add Makefile.inc
    git commit -m "Set version in Makefile.inc"
    git tag v$NEW_VERSION
    git checkout master -f
    git merge v$NEW_VERSION
    git push origin v$NEW_VERSION
    git push
fi


# Linux
ARCH=i686 make -f Makefile clean
ARCH=i686 make -f Makefile release

ARCH=x86-64 make -f Makefile clean
ARCH=x86-64 make -f Makefile release

# Windows
ARCH=i686 make -f Makefile.windows clean
ARCH=i686 make -f Makefile.windows release

ARCH=x86-64 make -f Makefile.windows clean
ARCH=x86-64 make -f Makefile.windows release


if test ! -z $ONLY_BUILD
then
    rsync -Pravdtze ssh rop-tool* t0x0sh@t0x0sh.org:~/www/t0x0sh/rop-tool/releases/$NEW_VERSION/
fi
