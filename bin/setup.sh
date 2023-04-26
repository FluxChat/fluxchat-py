#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")

which pip3 &> /dev/null || { echo 'ERROR: pip3 not found in PATH'; exit 1; }
which virtualenv &> /dev/null || { echo 'ERROR: virtualenv not found in PATH'; exit 1; }
which openssl &> /dev/null || { echo 'ERROR: openssl not found in PATH'; exit 1; }
which envsubst &> /dev/null || { echo 'ERROR: envsubst not found in PATH'; exit 1; }

export FLUXCHAT_CONFIG=${FLUXCHAT_CONFIG:-var/config1.json}
export FLUXCHAT_ADDRESS=${FLUXCHAT_ADDRESS:-0.0.0.0}
export FLUXCHAT_PORT=${FLUXCHAT_PORT:-25001}
export FLUXCHAT_DATA_DIR=${FLUXCHAT_DATA_DIR:-var/data1}
export FLUXCHAT_LOG_FILE=${FLUXCHAT_LOG_FILE:-fluxchat.log}

cd "${SCRIPT_BASEDIR}/.."
pwd

export FLUXCHAT_CONTACT=${FLUXCHAT_CONTACT:-public} # public, private or ip:port

echo "-> FLUXCHAT_CONFIG: ${FLUXCHAT_CONFIG}"
echo "-> FLUXCHAT_ADDRESS: ${FLUXCHAT_ADDRESS}"
echo "-> FLUXCHAT_PORT: ${FLUXCHAT_PORT}"
echo "-> FLUXCHAT_CONTACT_IP: ${FLUXCHAT_CONTACT_IP}"
echo "-> FLUXCHAT_CONTACT_PORT: ${FLUXCHAT_CONTACT_PORT}"
echo "-> FLUXCHAT_CONTACT: ${FLUXCHAT_CONTACT}"
echo "-> FLUXCHAT_DATA_DIR: ${FLUXCHAT_DATA_DIR}"

mkdir -p ${FLUXCHAT_DATA_DIR}
chmod go-rwx ${FLUXCHAT_DATA_DIR}

rsa_priv_key_file=${FLUXCHAT_DATA_DIR}/private_key.pem
rsa_pub_key_file=${FLUXCHAT_DATA_DIR}/public_key.pem
if ! test -f ${rsa_priv_key_file} ; then
	echo '-> generating rsa key'
	openssl genrsa -out ${rsa_priv_key_file} 4096

	echo '-> generating rsa public key'
	openssl rsa -in ${rsa_priv_key_file} -outform PEM -pubout -out ${rsa_pub_key_file}
fi

if [[ ! -d ./.venv ]]; then
	if ! virtualenv --system-site-packages -p python3 ./.venv ; then
		echo 'ERROR: could not install venv'
		exit 1
	fi
fi

source ./.venv/bin/activate
pip3 install -r requirements.txt

if ! test -f ${FLUXCHAT_CONFIG}; then
	echo '-> generating id'
	export FLUXCHAT_ID=$(./src/gen_id.py -f ${FLUXCHAT_DATA_DIR}/public_key.pem)

	echo '-> generating config'
	envsubst < ./config-example.json > ${FLUXCHAT_CONFIG}
fi
if ! test -f ${FLUXCHAT_DATA_DIR}/bootstrap.json; then
	echo '-> generating bootstrap'
	cp ./bootstrap.json ${FLUXCHAT_DATA_DIR}/bootstrap.json
fi
