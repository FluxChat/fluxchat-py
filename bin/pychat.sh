#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

source "./.venv/bin/activate"

./src/pychat_app.py -c var/node1.json
