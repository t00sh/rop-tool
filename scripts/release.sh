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
