# FluxChat

A decentralized, peer-to-peer, encrypted chat written in Python.

FluxChat uses asymetic-encryption to encrypt messages end-to-end. TLS is used to encrypt the traffic between single nodes. Kademlia algorithm is used to route messages and position nodes in the network.

## Project Outlines

The project outlines as described in my blog post about [Open Source Software Collaboration](https://blog.fox21.at/2019/02/21/open-source-software-collaboration.html).

- TBD

## Installation

The setup process for FluxChat involves installing the required Python dependencies and generating the necessary configuration files.

To start the setup process, run

```bash
./bin/setup.sh
```

The script utilizes `virtualenv` to create a virtual environment and install the required Python dependencies. The environment variables used during the setup process are optional. See a list of available environment variables in section 'Environment Variables' below.

If the private key file is not found, the `src/gen_rsa.py` script will be executed to generate the private key, public key, and a self-signed certificate. This can be also done by `openssl`.

Towards the end of the setup process, the script runs `envsubst` to substitute variables in the `config-example.json` template file with environment variables, generating the final configuration file.

For the setup we assume that FluxChat is running on a personal Computer in a Local Area Network (LAN), which is connected to the public Internet via a default gateway. By default FluxChat will listen on all network interfaces (0.0.0.0).

To setup another node, you can use environment variables.

```bash
export FLUXCHAT_CONFIG=var/config2.json
export FLUXCHAT_PORT=25002
export FLUXCHAT_DATA_DIR=var/data2
export FLUXCHAT_IPC_PORT=26002
./bin/setup.sh
```

## Configuration File

## Environment Variables

## Network

## External Documentation

- https://en.wikipedia.org/wiki/Kademlia
- https://en.wikipedia.org/wiki/X.509
- https://en.wikipedia.org/wiki/ASN.1
- https://en.wikipedia.org/wiki/Symmetric-key_algorithm
- https://en.wikipedia.org/wiki/Hybrid_cryptosystem
- https://medium.com/coinmonks/a-brief-overview-of-kademlia-and-its-use-in-various-decentralized-platforms-da08a7f72b8f
- [StackExchange: Should we sign-then-encrypt, or encrypt-then-sign?](https://crypto.stackexchange.com/questions/5458/should-we-sign-then-encrypt-or-encrypt-then-sign)
- [Don Davis: Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html)
- [pyca/cryptography](https://cryptography.io/en/latest/)
- [Lifetimes of cryptographic hash functions](https://valerieaurora.org/hash.html)
- [Announcing the first SHA1 collision](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html)

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
