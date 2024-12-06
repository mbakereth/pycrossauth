#!/bin/bash
tag=`grep '^ *version =' pyproject.toml | sed 's/.*"\([0-9]*\.[0-9]*\.[0-9]*\)".*/\1/'`
if [ $# = 1 ]; then
    msg=$1
else
    msg="Tag version $tag"
fi
git tag -a "v$tag" -m "$msg"
git push origin tag "v$tag"


