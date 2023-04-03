# PyChat

A decentralized, peer-to-peer, encrypted chat written in Python.

## Project Outlines

The project outlines as described in my blog post about [Open Source Software Collaboration](https://blog.fox21.at/2019/02/21/open-source-software-collaboration.html).

- TBD

## Installation

For the setup we assume that PyChat is running on a personal Computer in a Local Area Network, which is connected to the public Internet via a default gateway. By default PyChat will listen on all network interfaces (0.0.0.0).

```bash
./bin/setup.sh
```

To setup another node, use environment variables.

```bash
. .venv/bin/activate
export PYCHAT_CONFIG=var/config2.json
export PYCHAT_PORT=25002
export PYCHAT_DATA_DIR=var/data2
./bin/setup.sh
```

## Configuration

## Network

## External Documentation

- https://en.wikipedia.org/wiki/Kademlia
- https://medium.com/coinmonks/a-brief-overview-of-kademlia-and-its-use-in-various-decentralized-platforms-da08a7f72b8f
