#!/usr/bin/env python3

import argparse
from lib.cash import Cash

def main():
	parser = argparse.ArgumentParser(prog='cash', description='Cash')
	parser.add_argument('--data', type=str, nargs=1, required=True)
	parser.add_argument('--bits', type=int, nargs=1, required=True)
	# parser.add_argument('command')
	args = parser.parse_args()

	print(args)

	cash1 = Cash(args.data[0], args.bits[0])
	cycles = cash1.mine()
	print(cash1.proof)
	print(cash1.nonce)
	print(cycles)

	cash2 = Cash(args.data[0], args.bits[0])
	print(cash2.verify(cash1.proof, cash1.nonce))

if __name__ == '__main__':
	main()
