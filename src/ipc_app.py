#!/usr/bin/env python3

import os
import argparse

from lib.ipc import Ipc

def main():
	parser = argparse.ArgumentParser(prog='ipc_app', description='IPC App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')
	parser.add_argument('-t', '--target', type=str, nargs='?', required=True, help='Target to send message to')
	parser.add_argument('-s', '--subject', type=str, nargs='?', required=True, help='Subject')
	parser.add_argument('-m', '--message', type=str, nargs='?', required=True, help='Message to send')
	parser.add_argument('command')

	args = parser.parse_args()

	app = Ipc(args.config[0])
	app.start()

	if args.command == 'send':
		if app.send(args.target, args.subject, args.message):
			print('-> Message sent')
		else:
			print('-> Message not sent')

if __name__ == '__main__':
	main()
