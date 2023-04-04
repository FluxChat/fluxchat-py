
import unittest
from lib.client import Client
from lib.overlay import Node

class ClientTestCase(unittest.TestCase):
	def test_from_list(self):
		client = Client()
		client.from_list(['FC_test1', 'localhost', 25001])
		self.assertEqual(client.id, 'FC_test1')
		self.assertEqual(client.address, 'localhost')
		self.assertEqual(client.port, 25001)

	def test_inc_meetings(self):
		client = Client()
		client.inc_meetings()
		self.assertEqual(client.meetings, 1)

	def test_set_id(self):
		client = Client()
		client.set_id('FC_test1')
		self.assertEqual(client.node, 'FC_test1')

	def test_distance1(self):
		node = Node('FC_test1')
		client = Client()
		self.assertEqual(client.distance(node), 160)

	def test_distance2(self):
		node = Node('FC_test1')
		client = Client()
		client.set_id('FC_test2')
		self.assertTrue(client.distance(node) == 129)

	def test_eq1(self):
		client1 = Client()
		client1.set_id('FC_test1')
		client2 = Client()
		client2.set_id('FC_test1')
		self.assertTrue(client1 == client2)

	def test_eq2(self):
		client1 = Client()
		client2 = Client()
		self.assertFalse(client1 == client2)

	def test_eq3(self):
		client1 = Client()
		client1.set_id('FC_test1')
		client2 = Client()
		client2.set_id('FC_test2')
		self.assertFalse(client1 == client2)

	def test_eq4(self):
		client1 = Client()
		client1.set_id('FC_test1')
		self.assertFalse(client1 == 1)
