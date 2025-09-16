#!/bin/bash
version1=`cat VERSION | awk -F. '{print $1}'`
version2=`cat VERSION | awk -F. '{print $2}'`
version3=`cat VERSION | awk -F. '{print $3}'`

if [ $# = 0 ]; then
    echo "bumpversion.txt 1|2|3|x.y.z"
    echo "1 = major version"
    echo "2 = minor version"
    echo "3 = bug fix"
    exit 0
fi
if [ $1 == 1 ]; then
    version1=`expr $version1 + 1`
    version2=0
    version3=0
elif [ $1 == 2 ]; then
    version2=`expr $version2 + 1`
    version3=0
elif [ $1 == 3 ]; then
    version3=`expr $version3 + 1`
else
    nfields=`echo $1 | awk -F. '{print NF }'`
    version1=`echo $1 | awk -F. '{print $1 }'`
    version2=`echo $1 | awk -F. '{print $2 }'`
    version3=`echo $1 | awk -F. '{print $3 }'`
fi

echo "$version1.$version2.$version3" > VERSION

sed -E -i "" "s/current_version: \"[0-9]+\.[0-9]+\.[0-9]+\"/\"current_version\": \"$version1\.$version2\.$version3\"/" pyproject.toml

for file in `ls src/*/__init__.py`; do
    sed -E -i "" "s/__version__ = \"[0-9]+\.[0-9]+\.[0-9]+\"/__version__ = \"$version1\.$version2\.$version3\"/" $file
done


