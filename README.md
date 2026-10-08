# FluxChat

A decentralized, peer-to-peer, encrypted chat written in Python.

FluxChat uses asymetic-encryption to encrypt messages end-to-end. [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) is used to encrypt the traffic between single nodes. [Kademlia algorithm](https://en.wikipedia.org/wiki/Kademlia) is used to route messages and position nodes in the network.

## Quick Start

Dependencies:

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- gettext

Run this in your favourite shell, Bash.

```bash
brew install gettext uv
git clone https://github.com/FluxChat/fluxchat-py.git
cd fluxchat-py
./bin/setup.sh
./bin/start.sh
```

## Features

- Peer-to-peer connection without a central server.
- Send end-to-end messages with [asymmetric encryption]((https://en.wikipedia.org/wiki/Public-key_cryptography)).
- TLS encryption used to secure communication between individual nodes.

## Further Information

See [wiki](https://github.com/FluxChat/fluxchat-py/wiki) for more informations about

- [Get Started](wiki/)
- [Configuration File](wiki/)
- [Environment Variables](wiki/)

## Dev

```bash
uv run ./src/server_app.py --dev -c var/config1.json
uv run python -m debugpy --listen 0.0.0.0:5678 ./src/server_app.py --dev -c var/config1.json

cd src
uv run python -m unittest tests/test_mail.py

curl http://127.0.0.1:26002/v1/mails -s | jq
curl http://127.0.0.1:26002/v1/mails -s -X POST -d '{"subject":"hi","body":"SGVsbG8gV29ybGQ=","target":""}' | jq
curl http://127.0.0.1:26002/v1/queue -s | jq
```

```bash
export IS_UNITTEST=true
export PYTHONPATH=$PWD/src
uv run coverage run -m unittest tests.test_address_book.AddressBookTestCase.test_save_load
```

openssl rsa -pubin -inform PEM -in var/data1/public_key.pem -outform DER | openssl dgst -sha256 -c
