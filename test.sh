#!/bin/bash
if [ $# = 0 ]; then
    PYTHONPATH="./src:${PYTHONPATH}" dotenv -f .env.unittest run -- python -m unittest discover -s test -p 'test_*.py'
else
    PYTHONPATH="./src:${PYTHONPATH}" dotenv -f .env.unittest run -- python -m unittest $1
fi
