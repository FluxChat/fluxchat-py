#!/usr/bin/env bash

export IS_UNITTEST=true
SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

rm -rf tmp/tests
mkdir -p tmp/tests/data_default tmp/tests/data_custom

. .venv/bin/activate

set -x
coverage run -m unittest discover -s src
coverage html -d tmp/coverage
