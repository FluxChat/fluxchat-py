#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")

which pip3 &> /dev/null || { echo 'ERROR: pip3 not found in PATH'; exit 1; }
which virtualenv &> /dev/null || { echo 'ERROR: virtualenv not found in PATH'; exit 1; }
which openssl &> /dev/null || { echo 'ERROR: openssl not found in PATH'; exit 1; }
which envsubst &> /dev/null || { echo 'ERROR: envsubst not found in PATH'; exit 1; }
#which curl &> /dev/null || { echo 'ERROR: curl not found in PATH'; exit 1; }

export PYCHAT_CONFIG=${PYCHAT_CONFIG:-var/config1.json}
export PYCHAT_ADDRESS=${PYCHAT_ADDRESS:-0.0.0.0}
export PYCHAT_PORT=${PYCHAT_PORT:-25001}
export PYCHAT_DATA_DIR=${PYCHAT_DATA_DIR:-var/data1}

cd "${SCRIPT_BASEDIR}/.."
pwd

#$(curl -s https://httpbin.org/ip | jq -r .origin)
export PYCHAT_CONTACT_IP=${PYCHAT_CONTACT_IP:-127.0.0.1}
export PYCHAT_CONTACT_PORT=${PYCHAT_CONTACT_PORT:-${PYCHAT_PORT}}
export PYCHAT_CONTACT=${PYCHAT_CONTACT:-${PYCHAT_CONTACT_IP}:${PYCHAT_CONTACT_PORT}}

echo "-> PYCHAT_CONFIG: ${PYCHAT_CONFIG}"
echo "-> PYCHAT_ADDRESS: ${PYCHAT_ADDRESS}"
echo "-> PYCHAT_PORT: ${PYCHAT_PORT}"
echo "-> PYCHAT_CONTACT_IP: ${PYCHAT_CONTACT_IP}"
echo "-> PYCHAT_CONTACT_PORT: ${PYCHAT_CONTACT_PORT}"
echo "-> PYCHAT_CONTACT: ${PYCHAT_CONTACT}"
echo "-> PYCHAT_DATA_DIR: ${PYCHAT_DATA_DIR}"

mkdir -p ${PYCHAT_DATA_DIR}

rsa_priv_key_file=${PYCHAT_DATA_DIR}/privkey.pem
rsa_pub_key_file=${PYCHAT_DATA_DIR}/pubkey.pem
if ! test -f ${rsa_priv_key_file} ; then
	openssl genrsa -out ${rsa_priv_key_file} 4096
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

export PYCHAT_ID=$(./src/gen_id.py -f ${PYCHAT_DATA_DIR}/pubkey.pem)

if ! test -f ${PYCHAT_CONFIG}; then
	envsubst < ./config-example.json > ${PYCHAT_CONFIG}
fi
if ! test -f ${PYCHAT_DATA_DIR}/bootstrap.json; then
	cp ./bootstrap.json ${PYCHAT_DATA_DIR}/bootstrap.json
fi
