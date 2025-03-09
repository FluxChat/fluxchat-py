# FluxChat

A decentralized, peer-to-peer, encrypted chat written in Python.

FluxChat uses asymetic-encryption to encrypt messages end-to-end. [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) is used to encrypt the traffic between single nodes. [Kademlia algorithm](https://en.wikipedia.org/wiki/Kademlia) is used to route messages and position nodes in the network.

## Quick Start

Dependencies:

- Python 3
- [virtualenv](https://docs.python.org/3/library/venv.html)
- gettext

Run this in your favourite shell, Bash.

```bash
brew install gettext virtualenv
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
source ./.venv/bin/activate
./src/server_app.py --dev -c var/config1.json

cd src
python3 -m unittest tests/test_mail.py

./src/ipc_app.py mail -c var/config1.json -s Test -b 'Hello World' -t XYZ
./src/ipc_app.py list -c var/config2.json

./src/ipc_app.py -c var/config2.json list
./src/ipc_app.py -c var/config2.json read --uuid 4fbd8a82-05ac-4a30-9bad-4d9ff02661b2
```

```bash
export IS_UNITTEST=true
export PYTHONPATH=$PWD/src
coverage run -m unittest tests.test_address_book.AddressBookTestCase.test_save_load
```

openssl rsa -pubin -inform PEM -in var/data1/public_key.pem -outform DER | openssl dgst -sha256 -c
