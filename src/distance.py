#!/usr/bin/env python3

import argparse
from lib.node import Node
from lib.distance import Distance

def main():
	parser = argparse.ArgumentParser(prog='id', description='Diff ID')
	parser.add_argument('--id1', type=str, nargs=1, required=True, help='ID1')
	parser.add_argument('--id2', type=str, nargs=1, required=True, help='ID2')
	args = parser.parse_args()

	print('-> ID1: {}'.format(args.id1[0]))
	print('-> ID2: {}'.format(args.id2[0]))

	node1 = Node.parse(args.id1[0])
	node2 = Node.parse(args.id2[0])

	print('-> ID1 Valid: {}'.format(node1.has_valid_id()))
	print('-> ID2 Valid: {}'.format(node2.has_valid_id()))
	print('-> Node1: {}'.format(node1))
	print('-> Node2: {}'.format(node2))

	dist = Distance(node1, node2)
	print('-> Distance: {}'.format(dist))

if __name__ == '__main__':
	main()
