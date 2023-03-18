#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")

which pip3 &> /dev/null || { echo 'ERROR: pip3 not found in PATH'; exit 1; }
which virtualenv &> /dev/null || { echo 'ERROR: virtualenv not found in PATH'; exit 1; }

cd "${SCRIPT_BASEDIR}/.."
pwd

mkdir -p var/data1 tmp

if [[ ! -d ./.venv ]]; then
	if ! virtualenv --system-site-packages -p python3 ./.venv ; then
		echo 'ERROR: could not install venv'
		exit 1
	fi
fi

source ./.venv/bin/activate
pip3 install -r requirements.txt

if ! test -f ./var/config.json; then
	cp ./config-example.json ./var/config.json
fi
