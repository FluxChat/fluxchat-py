#!/usr/bin/env bash

export PYTHONUNBUFFERED=1
export FLUXCHAT_KEY_PASSWORD=${FLUXCHAT_KEY_PASSWORD:-password}

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

export ALLOW_SELF_CONNECT=1 # only for development
source ./.venv/bin/activate
./src/server_app.py -c var/config1.json
