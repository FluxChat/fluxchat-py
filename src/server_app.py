#!/usr/bin/env python3


from signal import SIGINT, signal
from argparse import ArgumentParser
from lib.app.server import ServerApp

def main():
	parser = ArgumentParser(prog='server_app', description='Server App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')
	parser.add_argument('--dev', default=False, action='store_true')
	parser.add_argument('-l', '--loglevel', help='Provide logging level. Example --loglevel debug')

	args = parser.parse_args()

	app = ServerApp(args.config[0], args.dev, args.loglevel)

	signal(SIGINT, lambda sig, frame: app.shutdown('SIGINT'))

	app.start()
	try:
		app.run()
	except KeyboardInterrupt:
		app.shutdown('KeyboardInterrupt')

if __name__ == '__main__':
	main()
