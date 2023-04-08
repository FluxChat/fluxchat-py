#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

source ./.venv/bin/activate
./src/ipc_app.py -c var/config1.json $*
