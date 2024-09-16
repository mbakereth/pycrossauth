#!/bin/bash
if [ $# = 0 ]; then
    PYTHONPATH="./src:${PYTHONPATH}" dotenv -e .env.unittest python -m unittest test/**/test_*.py test/test_*.py $*
else
    PYTHONPATH="./src:${PYTHONPATH}" dotenv -e .env.unittest python -m unittest test/**/test_*$1*.py
fi
