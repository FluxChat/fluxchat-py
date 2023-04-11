#!/usr/bin/env python3

import sys
import signal
import os
import argparse

from lib.pychat import PyChat

def main():
	parser = argparse.ArgumentParser(prog='server_app', description='Server App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')

	args = parser.parse_args()

	print('-> pid:', os.getpid())

	app = PyChat(args.config[0])

	signal.signal(signal.SIGINT, lambda sig, frame: app.shutdown())

	app.start()
	try:
		app.run()
	except KeyboardInterrupt:
		print()
		app.shutdown()

if __name__ == '__main__':
	main()
