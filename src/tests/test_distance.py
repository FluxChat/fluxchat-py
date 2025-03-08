
from unittest import TestCase
from lib.overlay import Distance, Node


class DistanceTestCase(TestCase):
	def test_str(self):
		node1 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dG')
		node2 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		distance1 = Distance(node1, node2)
		self.assertEqual(str(distance1), 'Distance(1)')

	def test_distance_lt(self):
		node1 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dG')
		node2 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		node3 = Node('FC_6iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		distance1 = Distance(node1, node2)
		distance2 = Distance(node1, node3)
		self.assertTrue(distance1 < distance2)

	def test_distance_eq1(self):
		node1 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		node2 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		node3 = Node('FC_6iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		node4 = Node('FC_6iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		distance1 = Distance(node1, node3)
		distance2 = Distance(node2, node4)
		self.assertEqual(distance1, distance2)

	def test_distance_eq2(self):
		node1 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		node2 = Node('FC_7iqZKQZ45E9kb8fviqo8iP9Hex7qj35qmHMa6okkB1dF')
		distance1 = Distance()
		self.assertFalse(distance1 == 'x')
