#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

./bin/pychat.sh 1> /dev/null 2> /dev/null < /dev/null &
if test $? -eq 0 ; then
	sleep 0.2
	pid_file=var/data1/pychat.pid
	pid=$(cat ${pid_file})
	echo "-> started: ${pid}"
else
	echo "-> failed"
fi
