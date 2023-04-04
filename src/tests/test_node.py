
import unittest
from lib.overlay import Node, Distance

class NodeTestCase(unittest.TestCase):
	def setUp(self):
		self.node1 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjN')

	def test_str(self):
		self.assertEqual(str(self.node1), 'Node(FC_2QVEiC82QXQVg97AAHmjiMsmnNjN)')

	def test_eq1(self):
		self.assertEqual(Node('FC_123456788'), Node('FC_123456788'))

	def test_eq2(self):
		self.assertFalse(Node('FC_123456788') == Node('FC_123456789'))

	def test_eq3(self):
		self.assertFalse(Node('FC_123456788') == 'FC_123456789')

	def test_eq4(self):
		self.assertFalse(Node('FC_123456788') == 123)

	def test_has_valid_id1(self):
		self.assertTrue(self.node1.has_valid_id())

	def test_has_valid_id2(self):
		self.assertFalse(Node('XYZ').has_valid_id())

	def test_distance(self):
		node2 = Node('FC_2QVEiC82QXQVg97AAHmjiMsmnNjN')
		distance = self.node1.distance(node2)
		self.assertEqual(type(distance), Distance)
