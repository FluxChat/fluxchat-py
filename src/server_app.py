#!/usr/bin/env python3

from asyncio import run as arun, create_task, get_event_loop, ensure_future
from signal import SIGINT, signal as signal_fn
import signal
from argparse import ArgumentParser
from lib.app.server import ServerApp


async def main():
	parser = ArgumentParser(prog='server_app', description='Server App')
	parser.add_argument('-c', '--config', type=str, required=True, help='Path to Config File')
	parser.add_argument('--dev', default=False, action='store_true')
	parser.add_argument('-l', '--loglevel', help='Provide logging level. Example --loglevel debug')

	args = parser.parse_args()

	app = ServerApp(args.config, args.dev, args.loglevel)

	async def asigint_fn(sig, frame=None):
		print('-> server_app.py sigint_fn')
		await app.shutdown('SIGINT')

	# I don't know what I'm doing. Some SO magic.
	loop = get_event_loop()
	for signame in ('SIGINT', 'SIGTERM'):
		loop.add_signal_handler(getattr(signal, signame),
								lambda: ensure_future(asigint_fn(signame)))

	app.start()
	try:
		await app.run()
	except KeyboardInterrupt:
		print('-> server_app.py KeyboardInterrupt')
		await app.shutdown('KeyboardInterrupt')

if __name__ == '__main__':
	arun(main())
