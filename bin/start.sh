#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

./bin/pychat.sh 1>> var/data1/stdout.log 2>&1 < /dev/null &
if test $? -eq 0 ; then
	echo "-> started"
else
	echo "-> failed"
fi
