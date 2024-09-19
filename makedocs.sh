#!/bin/bash
sphinx-apidoc -o docs src/
cd docs
make html

