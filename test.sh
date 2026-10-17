#!/bin/bash
export PYTHONPATH="./venv/lib/python3.13/site-packages:./src:./test"
echo $PYTHONPATH
if [ $# = 0 ]; then
    dotenv -f .env.unittest run -- python -m unittest discover -s test -p 'test_*.py' -v
else
    dotenv -f .env.unittest run -- python -m unittest $1
fi

