#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")

which pip3 &> /dev/null || { echo 'ERROR: pip3 not found in PATH'; exit 1; }
which virtualenv &> /dev/null || { echo 'ERROR: virtualenv not found in PATH'; exit 1; }
which envsubst &> /dev/null || { echo 'ERROR: envsubst not found in PATH'; exit 1; }

export FLUXCHAT_CONFIG=${FLUXCHAT_CONFIG:-var/config1.json}
export FLUXCHAT_ADDRESS=${FLUXCHAT_ADDRESS:-0.0.0.0}
export FLUXCHAT_PORT=${FLUXCHAT_PORT:-25001}
export FLUXCHAT_CONTACT=${FLUXCHAT_CONTACT:-public} # public, private or ip:port
export FLUXCHAT_DATA_DIR=${FLUXCHAT_DATA_DIR:-var/data1}
export FLUXCHAT_LOG_FILE=${FLUXCHAT_LOG_FILE:-fluxchat.log}
export FLUXCHAT_IPC_PORT=${FLUXCHAT_IPC_PORT:-26001}
export FLUXCHAT_KEY_PASSWORD=${FLUXCHAT_KEY_PASSWORD:-password}
export FLUXCHAT_KEY_DERIVATION_ITERATIONS=${FLUXCHAT_KEY_DERIVATION_ITERATIONS:-600000}

cd "${SCRIPT_BASEDIR}/.."
pwd

echo "-> FLUXCHAT_CONFIG: ${FLUXCHAT_CONFIG}"
echo "-> FLUXCHAT_ADDRESS: ${FLUXCHAT_ADDRESS}"
echo "-> FLUXCHAT_PORT: ${FLUXCHAT_PORT}"
echo "-> FLUXCHAT_CONTACT: ${FLUXCHAT_CONTACT}"
echo "-> FLUXCHAT_DATA_DIR: ${FLUXCHAT_DATA_DIR}"
echo "-> FLUXCHAT_LOG_FILE: ${FLUXCHAT_LOG_FILE}"
echo "-> FLUXCHAT_KEY_DERIVATION_ITERATIONS: ${FLUXCHAT_KEY_DERIVATION_ITERATIONS}"

mkdir -p ${FLUXCHAT_DATA_DIR}
chmod go-rwx ${FLUXCHAT_DATA_DIR}

if [[ -d ./.venv ]]; then
	source ./.venv/bin/activate
else
	if ! virtualenv --system-site-packages -p python3 ./.venv ; then
		echo 'ERROR: could not install venv'
		exit 1
	fi
	echo '-> installing requirements'
	if ! pip3 install -r requirements.txt ; then
		echo 'ERROR: could not install requirements'
		exit 1
	fi
fi

rsa_priv_key_file=${FLUXCHAT_DATA_DIR}/private_key.pem
if test -f ${rsa_priv_key_file} ; then
	echo '-> generating id'
	FLUXCHAT_ID=$(./src/gen_id.py -f ${FLUXCHAT_DATA_DIR}/public_key.pem)
else
	echo '-> generating rsa keys'
	FLUXCHAT_ID=$(./src/gen_rsa.py)
fi
echo "-> FLUXCHAT_ID: ${FLUXCHAT_ID}"
export FLUXCHAT_ID

if ! test -f ${FLUXCHAT_CONFIG}; then
	echo '-> generating config'
	touch ${FLUXCHAT_CONFIG}
	chmod go-rwx ${FLUXCHAT_CONFIG}
	envsubst < ./config-example.json > ${FLUXCHAT_CONFIG}
fi
if ! test -f ${FLUXCHAT_DATA_DIR}/bootstrap.json; then
	echo '-> generating bootstrap'
	echo '[]' > ${FLUXCHAT_DATA_DIR}/bootstrap.json
fi
