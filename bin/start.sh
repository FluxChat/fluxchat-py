#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

./bin/server.sh 1> /dev/null 2> /dev/null < /dev/null &
if test $? -eq 0 ; then
	sleep 1
	pid_file=var/data1/server.pid
	if test -f ${pid_file} ; then
		pid=$(cat ${pid_file})
		echo "-> started: ${pid}"
	else
		echo "-> started"
	fi
else
	echo "-> failed"
fi
