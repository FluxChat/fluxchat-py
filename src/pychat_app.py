#!/usr/bin/env python3

import os
import argparse

from lib.pychat import PyChat

def main():
	parser = argparse.ArgumentParser(prog='server_app', description='Server App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')
	# parser.add_argument('command', choices=['server'])

	args = parser.parse_args()

	print('-> pid:', os.getpid())

	app = PyChat(args.config[0])
	try:
		app.run()
	except KeyboardInterrupt as e:
		print()
		app.shutdown()

	print('-> done')

if __name__ == '__main__':
	main()
