#!/usr/bin/env python3

import signal
import argparse

from lib.fluxchat import FluxChat

def main():
	parser = argparse.ArgumentParser(prog='server_app', description='Server App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')
	parser.add_argument('--dev', default=False, action='store_true')
	parser.add_argument('-l', '--loglevel', help='Provide logging level. Example --loglevel debug')

	args = parser.parse_args()

	app = FluxChat(args.config[0], args.dev, args.loglevel)

	signal.signal(signal.SIGINT, lambda sig, frame: app.shutdown('SIGINT'))

	app.start()
	try:
		app.run()
	except KeyboardInterrupt:
		app.shutdown('KeyboardInterrupt')

if __name__ == '__main__':
	main()
