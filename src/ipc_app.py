#!/usr/bin/env python3

import os
import argparse

from lib.app.ipc import IpcApp

def main():
	parser = argparse.ArgumentParser(prog='ipc_app', description='IPC App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')
	parser.add_argument('-t', '--target', type=str, nargs='?', required=False, help='Target to send message to')
	parser.add_argument('-s', '--subject', type=str, nargs='?', required=False, help='Subject')
	parser.add_argument('-m', '--message', type=str, nargs='?', required=False, help='Message to send')
	parser.add_argument('command')

	args = parser.parse_args()

	app = IpcApp(args.config[0])
	app.start()

	if args.command == 'send':
		if app.send(args.target, args.subject, args.message):
			print('-> Message sent')
		else:
			print('-> Message not sent')
	elif args.command == 'save':
		app.save()

if __name__ == '__main__':
	main()
