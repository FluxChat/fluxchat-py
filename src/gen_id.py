#!/usr/bin/env python3

# Generate ID from Public Key

import argparse
from lib.helper import generate_id_from_public_key_file

def main():
	parser = argparse.ArgumentParser(prog='id', description='Get ID')
	parser.add_argument('-f', '--file', type=str, nargs=1, required=True, help='Path to Public Key File')
	args = parser.parse_args()

	print(generate_id_from_public_key_file(args.file[0]))

if __name__ == '__main__':
	main()
