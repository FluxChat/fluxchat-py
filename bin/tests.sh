#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

mkdir -p tmp/tests
rm -rf tmp/tests

. .venv/bin/activate

set -x
python -m unittest discover -s src

coverage run -m unittest discover -s src
#coverage report
coverage html -d tmp/coverage
