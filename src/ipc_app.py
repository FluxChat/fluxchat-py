#!/usr/bin/env python3

import os
import argparse

from lib.app.ipc import IpcApp

def main():
	parser = argparse.ArgumentParser(prog='ipc_app', description='IPC App')
	parser.add_argument('-c', '--config', type=str, required=True, help='Path to Config File')
	parser.add_argument('-t', '--target', type=str, nargs='?', required=False, help='Target to send mail to')
	parser.add_argument('-s', '--subject', type=str, nargs='?', required=False, help='Subject')
	parser.add_argument('-b', '--body', type=str, nargs='?', required=False, help='Text')
	parser.add_argument('-n', '--new', action='store_true', required=False, help='List only new mails')
	parser.add_argument('-u', '--uuid', type=str, nargs='?', required=False, help='UUID of mail to read')
	parser.add_argument('-l', '--loglevel', default='warning', help='Provide logging level. Example --loglevel debug')
	parser.add_argument('command')

	args = parser.parse_args()
	# print(args)

	app = IpcApp(args.config, args.loglevel.upper())
	app.start()

	if args.command == 'mail':
		print('-> Mail command')
		app.send_mail_command(args.target, args.subject, args.body)
		app.stop()

	elif args.command == 'list':
		print('-> List command')
		app.list_mails_command(args.new)

	elif args.command == 'read':
		print('-> Read command')
		app.read_mail_command(args.uuid)

	elif args.command == 'save':
		print('-> Save command')
		app.save_command()
		app.stop()

	try:
		app.run()
	except KeyboardInterrupt:
		print()
		app.shutdown('KeyboardInterrupt')

if __name__ == '__main__':
	main()
