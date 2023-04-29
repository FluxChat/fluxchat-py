# FluxChat

A decentralized, peer-to-peer, encrypted chat written in Python.

## Project Outlines

The project outlines as described in my blog post about [Open Source Software Collaboration](https://blog.fox21.at/2019/02/21/open-source-software-collaboration.html).

- TBD

## Installation

For the setup we assume that FluxChat is running on a personal Computer in a Local Area Network, which is connected to the public Internet via a default gateway. By default FluxChat will listen on all network interfaces (0.0.0.0).

```bash
./bin/setup.sh
```

To setup another node, use environment variables.

```bash
. .venv/bin/activate
export FLUXCHAT_CONFIG=var/config2.json
export FLUXCHAT_PORT=25002
export FLUXCHAT_DATA_DIR=var/data2
./bin/setup.sh
```

## Configuration File

## Environment Variables

## Network

## External Documentation

- https://en.wikipedia.org/wiki/Kademlia
- https://medium.com/coinmonks/a-brief-overview-of-kademlia-and-its-use-in-various-decentralized-platforms-da08a7f72b8f

## Dev

```bash
source ./.venv/bin/activate
./src/server_app.py --dev -c var/config1.json

cd src
python3 -m unittest tests/test_mail.py

./src/ipc_app.py mail -c var/config1.json -t XYZ -s Test1 -b 'Hello World'
```

```bash
export IS_UNITTEST=true
export PYTHONPATH=$PWD/src
coverage run -m unittest tests.test_address_book.AddressBookTestCase.test_save_load
```
