#!/usr/bin/env bash

export DATE=$(date +"%F %T %z")
SCRIPT_BASEDIR=$(dirname "$0")
cd "${SCRIPT_BASEDIR}/.."

echo 'Origin IP'
curl -s https://httpbin.org/ip

# Test SSH.
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${DEPLOY_USER}@${DEPLOY_HOST} 'date +"%F %T %z"'

# Push files.
echo "rsync to '${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}'"
rsync -4vurtc --chmod=Du=rwx,Dgo=rx,Fu=rw,Fog=r -e 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' tmp/coverage/ "${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}"
