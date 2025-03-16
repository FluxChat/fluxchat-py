#!/usr/bin/env python3

from asyncio import run as arun
from signal import SIGINT, signal as signal_fn
import signal
from argparse import ArgumentParser
from lib.app.gui import GuiApp


async def main():
	parser = ArgumentParser(prog='server_app', description='GUI App')
	parser.add_argument('-c', '--config', type=str, required=True, help='Path to Config File')
	parser.add_argument('--dev', default=False, action='store_true')
	parser.add_argument('-l', '--loglevel', help='Provide logging level. Example --loglevel debug')

	args = parser.parse_args()

	app = GuiApp(args.config, args.dev, args.loglevel)

	app.start()
	try:
		await app.run()
	except KeyboardInterrupt:
		print('-> server_app.py KeyboardInterrupt')

if __name__ == '__main__':
	arun(main())
