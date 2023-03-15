#!/usr/bin/env python3

import os
import argparse

from lib.pychat import PyChat

def main():
	parser = argparse.ArgumentParser(prog='pychat_app', description='PyChat App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')

	args = parser.parse_args()

	print('-> pid:', os.getpid())

	app = PyChat(args.config[0])
	app.run()

	print('-> done')

if __name__ == '__main__':
	main()
