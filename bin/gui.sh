#!/usr/bin/env bash

export PYTHONUNBUFFERED=1

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

source ./.venv/bin/activate
./src/gui_app.py -c var/config1.json
