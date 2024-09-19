#!/bin/bash
if [ $# = 0 ]; then
    PYTHONPATH="./src:${PYTHONPATH}" dotenv -e .env.unittest python -m unittest discover -s test -p 'test_*.py'
else
    PYTHONPATH="./src:${PYTHONPATH}" dotenv -e .env.unittest python -m unittest $1
fi
