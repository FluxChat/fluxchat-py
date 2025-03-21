#!/usr/bin/env python3

# Generate Test Data

import datetime as dt
from argparse import ArgumentParser
from lib.helper import generate_test_id


def main():
	parser = ArgumentParser(prog='id', description='Generate Random Data')
	parser.add_argument('command')
	parser.add_argument('-f', '--file', type=str, nargs=1, help='File Path')
	parser.add_argument('-n', '--number', type=int, nargs=1, help='Number of Test Data', default=[100])
	parser.add_argument('--seen-at', type=str, nargs=1)
	parser.add_argument('--meetings', type=int, nargs=1)
	parser.add_argument('--bootstrap', default=False, action='store_true')
	args = parser.parse_args()

	print(args.command)

	# if args.command == 'ab':
	# 	print('-> AddressBook')

	# 	seen_at = dt.datetime.strptime(args.seen_at[0], '%Y-%m-%d %H:%M:%S')  if args.seen_at is not None else None
	# 	meetings = args.meetings[0] if args.meetings is not None else None
	# 	bootstrap = args.bootstrap

	# 	address_book = AddressBook(args.file[0])

	# 	for i in range(0, args.number[0]):
	# 		c_id = generate_test_id()
	# 		print('-> c_id: {}'.format(c_id))
	# 		client = address_book.add_client(c_id, 'public', 26000 + i)
	# 		if seen_at is not None:
	# 			client.seen_at = seen_at
	# 		if meetings is not None:
	# 			client.meetings = meetings
	# 		if bootstrap is not None:
	# 			client.is_bootstrap = bootstrap

	# 	address_book.save()

if __name__ == '__main__':
	main()
