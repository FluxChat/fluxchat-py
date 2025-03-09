#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

pid_file=var/data1/server.pid
if test -f ${pid_file} ; then
	echo "-> found pid file"

	pid=$(cat ${pid_file})
	if [[ -z "${pid}" ]]; then
		echo "-> pid file is empty"
		exit 1
	fi
	echo "-> pid: ${pid}"

	echo "-> killing process with SIGKILL"
	kill -SIGKILL ${pid}

	rm -f ${pid_file}
else
	echo "-> no pid file found"
fi
