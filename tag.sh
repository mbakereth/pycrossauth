#!/bin/bash
tag=`cat VERSION`
if [ $# = 1 ]; then
    msg=$1
else
    msg="Tag version $tag"
fi
git tag -a "v$tag" -m "$msg"
git push origin tag "v$tag"


