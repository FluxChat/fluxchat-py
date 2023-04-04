
import unittest
from lib.overlay import Distance, Node

class DistanceTestCase(unittest.TestCase):
	def test_str(self):
		node1 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjN')
		node2 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjM')
		distance1 = Distance(node1, node2)
		self.assertEqual(str(distance1), 'Distance(1)')

	def test_distance_lt(self):
		node1 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjN')
		node2 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjM')
		node3 = Node('FC_1QVEiC82QXQVg97AAHmjiMsmnNjM')
		distance1 = Distance(node1, node2)
		distance2 = Distance(node1, node3)
		self.assertTrue(distance1 < distance2)

	def test_distance_eq1(self):
		node1 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjM')
		node2 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjM')
		node3 = Node('FC_1QVEiC82QXQVg97AAHmjiMsmnNjM')
		node4 = Node('FC_1QVEiC82QXQVg97AAHmjiMsmnNjM')
		distance1 = Distance(node1, node3)
		distance2 = Distance(node2, node4)
		self.assertEqual(distance1, distance2)

	def test_distance_eq2(self):
		node1 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjM')
		node2 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjM')
		distance1 = Distance()
		self.assertFalse(distance1 == 'x')
