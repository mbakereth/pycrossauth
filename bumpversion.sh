#!/bin/bash

if [ $# = 0 ]; then
    echo "bumpversion.txt 1|2|3"
    echo "1 = major version"
    echo "2 = minor version"
    echo "3 = bug fix"
    exit 0
fi
if [ $1 = "1" ]; then
    bumpver update --major
elif [ $1 = "2" ]; then
    bumpver update --minor
else
    bumpver update --patch
fi
