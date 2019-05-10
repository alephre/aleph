#!/bin/sh
#
# Generate version.txt file on commits
#

FILENAME='version.txt'

exec 1>&2
branch=`git rev-parse --abbrev-ref HEAD`
shorthash=`git log --pretty=format:'%h' -n 1`
revcount=`git log --oneline | wc -l`
latesttag=`git describe --tags --abbrev=0 --always`

VERSION="$branch $latesttag $revcount $shorthash"
echo $VERSION > $FILENAME
