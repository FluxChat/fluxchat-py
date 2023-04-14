#!/usr/bin/env python3

import argparse
from lib.cash import Cash

def main():
	parser = argparse.ArgumentParser(prog='cash', description='Cash')
	parser.add_argument('--data', type=str, nargs=1, required=True)
	parser.add_argument('--bits', type=int, nargs=1, required=True)
	args = parser.parse_args()

	print(args)

	cash = Cash()
	cycles = cash.mine(args.data[0].encode(), args.bits[0])
	print(cash.proof)
	print(cash.nonce)
	print(cycles)

if __name__ == '__main__':
	main()
