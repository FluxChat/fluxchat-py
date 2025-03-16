#!/usr/bin/env bash

SCRIPT_BASEDIR=$(dirname "$0")

export FLUXCHAT_CONFIG=${FLUXCHAT_CONFIG:-./var/config1.json}
export FLUXCHAT_ADDRESS=${FLUXCHAT_ADDRESS:-0.0.0.0}
export FLUXCHAT_PORT=${FLUXCHAT_PORT:-25001}
export FLUXCHAT_CONTACT=${FLUXCHAT_CONTACT:-public} # public, private or ip:port
export FLUXCHAT_DATA_DIR=${FLUXCHAT_DATA_DIR:-./var/data1}
export FLUXCHAT_LOG_FILE=${FLUXCHAT_LOG_FILE:-fluxchat.log}
export FLUXCHAT_IPC_PORT=${FLUXCHAT_IPC_PORT:-26001}
export FLUXCHAT_RESTAPI_PORT=${FLUXCHAT_RESTAPI_PORT:-26002}
export FLUXCHAT_KEY_PASSWORD=${FLUXCHAT_KEY_PASSWORD:-password}
export FLUXCHAT_KEY_DERIVATION_ITERATIONS=${FLUXCHAT_KEY_DERIVATION_ITERATIONS:-600000}

function catch_dep() {
	local exit_code=$?
	if [[ $exit_code -eq 3 ]] ; then
		echo 'ERROR: missing dependencies'
	fi
}

trap catch_dep EXIT

cd "${SCRIPT_BASEDIR}/.."
echo "current directory: $PWD"

arg1="$1"

# Dependencies
if [[ $arg1 == '--skip' ]] ; then
	echo '-> skipping dependencies auto-install'
else
	kernel_name=$(uname -s)
	if [[ -z "${kernel_name}" ]] ; then
		echo '-> kernel name is empty'
		echo '-> skipping dependencies auto-install'
	else
		if [[ "${kernel_name}" == Darwin ]] ; then
			echo '-> macOS detected'
			brew_bin=$(which brew)
			if [[ -z "${brew_bin}" ]] ; then
				echo '-> no brew binary found'
				echo '-> skipping dependencies auto-install'
			else
				echo '-> homebrew detected'
				if ${brew_bin} --version ; then
					echo -n '-> Should we try to install the dependencies using homebrew? [y/n] '
					read -r answer
					if [[ "${answer}" == 'y' ]] ; then
						echo '-> You selected "yes"'
						sleep 2
						echo '-> run brew install command'
						if ${brew_bin} install gettext virtualenv ; then
							echo '-> homebrew installation complete'
						else
							echo "ERROR: homebrew failed: $?"
						fi
					else
						echo '-> You selected "no"'
						echo '-> skipping dependencies auto-install'
						sleep 2
					fi
				else
					echo 'WARNING: cannot run homebrew. You have to install the dependecies manually.'
				fi
			fi
		elif [[ "${kernel_name}" == Linux ]] ; then
			echo '-> Linux detected'
			sudo_bin=$(which sudo)
			aptget_bin=$(which apt-get)
			if [[ -z "${aptget_bin}" ]] ; then
				echo '-> no apt-get binary found'
				echo '-> skipping dependencies auto-install'
			else
				echo '-> apt-get detected'
				if ${aptget_bin} --version ; then
					echo -n '-> Should we try to install the dependencies using sudo apt-get? [y/n] '
					read -r answer
					if [[ "${answer}" == 'y' ]] ; then
						echo '-> You selected "yes"'
						sleep 2
						echo '-> run sudo apt-get install command'
						if ${sudo_bin} ${aptget_bin} install python3-virtualenv ; then
							echo '-> apt-get installation complete'
						else
							echo "ERROR: apt-get failed: $?"
						fi
					else
						echo '-> You selected "no"'
						echo '-> skipping dependencies auto-install'
						sleep 2
					fi
				else
					echo 'WARNING: cannot run apt-get. You have to install the dependecies manually.'
				fi
			fi
		fi
	fi
fi

which pip3 &> /dev/null || { echo 'ERROR: pip3 not found in PATH'; exit 3; }
which virtualenv &> /dev/null || { echo 'ERROR: virtualenv not found in PATH'; exit 3; }
which envsubst &> /dev/null || { echo 'ERROR: envsubst not found in PATH'; exit 3; }

echo "-> FLUXCHAT_CONFIG: ${FLUXCHAT_CONFIG}"
echo "-> FLUXCHAT_ADDRESS: ${FLUXCHAT_ADDRESS}"
echo "-> FLUXCHAT_PORT: ${FLUXCHAT_PORT}"
echo "-> FLUXCHAT_CONTACT: ${FLUXCHAT_CONTACT}"
echo "-> FLUXCHAT_DATA_DIR: ${FLUXCHAT_DATA_DIR}"
echo "-> FLUXCHAT_LOG_FILE: ${FLUXCHAT_LOG_FILE}"
echo "-> FLUXCHAT_KEY_DERIVATION_ITERATIONS: ${FLUXCHAT_KEY_DERIVATION_ITERATIONS}"

mkdir -p ${FLUXCHAT_DATA_DIR}
chmod go-rwx ${FLUXCHAT_DATA_DIR}

if ! virtualenv --system-site-packages -p python3 ./.venv ; then
	echo 'ERROR: could not install venv'
	exit 1
fi
if [[ -d ./.venv ]]; then
	source ./.venv/bin/activate
fi
echo '-> installing requirements'
if ! pip3 install -r requirements.txt ; then
	echo 'ERROR: could not install requirements'
	exit 1
fi


rsa_priv_key_file=${FLUXCHAT_DATA_DIR}/private_key.pem
if test -f ${rsa_priv_key_file} ; then
	echo '-> generating id'
	FLUXCHAT_ID=$(./src/gen_id.py -f ${FLUXCHAT_DATA_DIR}/public_key.pem)
	status=$?
	echo "-> gen_id.py status: '${status}'"
else
	echo '-> generating rsa keys'
	FLUXCHAT_ID=$(./src/gen_rsa.py)
	status=$?
	echo "-> gen_rsa.py status: '${status}'"
fi

echo "-> FLUXCHAT_ID: '${FLUXCHAT_ID}'"
export FLUXCHAT_ID

if [[ -z ${FLUXCHAT_ID} ]]; then
	echo 'ERROR: could not generate id'
	exit 1
fi

if ! test -f ${FLUXCHAT_CONFIG}; then
	echo '-> generating config'
	touch ${FLUXCHAT_CONFIG}
	chmod go-rwx ${FLUXCHAT_CONFIG}
	envsubst < ./config-example.json > ${FLUXCHAT_CONFIG}
fi
if ! test -f ${FLUXCHAT_DATA_DIR}/bootstrap.json; then
	echo '-> generating bootstrap'
	echo '["bootstrap.fluxchat.dev:25001"]' > ${FLUXCHAT_DATA_DIR}/bootstrap.json
fi
