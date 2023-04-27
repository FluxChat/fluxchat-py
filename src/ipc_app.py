#!/usr/bin/env python3

import os
import argparse

from lib.app.ipc import IpcApp

def main():
	parser = argparse.ArgumentParser(prog='ipc_app', description='IPC App')
	parser.add_argument('-c', '--config', type=str, nargs=1, required=True, help='Path to Config File')
	parser.add_argument('-t', '--target', type=str, nargs='?', required=False, help='Target to send mail to')
	parser.add_argument('-s', '--subject', type=str, nargs='?', required=False, help='Subject')
	parser.add_argument('-b', '--body', type=str, nargs='?', required=False, help='Text')
	parser.add_argument('command')

	args = parser.parse_args()

	app = IpcApp(args.config[0])
	app.start()

	if args.command == 'mail':
		if app.send_mail(args.target, args.subject, args.body):
			print('-> Mail sent')
		else:
			print('-> Mail not sent')
	elif args.command == 'save':
		app.save()

if __name__ == '__main__':
	main()
