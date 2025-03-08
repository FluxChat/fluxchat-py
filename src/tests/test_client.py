
from unittest import TestCase
from lib.client import Client
from lib.overlay import Node


class ClientTestCase(TestCase):
	def test_str(self):
		client = Client()
		client.uuid = 'test'
		client.address = 'localhost'
		client.port = 25001
		client.id = 'FC_test1'
		client.conn_mode = 99
		client.dir_mode = 't'
		client.auth = 3
		client.actions = ['a', 'b', 'c', 'd']

		self.assertEqual(str(client), 'Client(test,localhost:25001,ID=FC_test1,c=99,d=t,a=3,ac=4)')

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
		distance = client.distance(node)
		self.assertEqual(str(distance), 'Distance(256)')
		self.assertEqual(client.distance(node), 256)

	def test_distance2(self):
		node = Node('FC_test1')
		client = Client()
		client.set_id('FC_test2')
		distance = client.distance(node)
		self.assertEqual(str(distance), 'Distance(225)')
		self.assertTrue(client.distance(node) == 225)

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

	def test_eq2b(self):
		client1 = Client()
		client1.uuid = 'x'
		client2 = Client()
		client2.uuid = ''
		self.assertFalse(client1 == client2)

	def test_eq2c(self):
		client1 = Client()
		client1.uuid = ''
		client2 = Client()
		client2.uuid = 'y'
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

	def test_eq5(self):
		client1 = Client()
		client1.uuid = 'y'
		client2 = Client()
		client2.uuid = 'y'
		self.assertTrue(client1 == client2)

	def test_eq6(self):
		client1 = Client()
		client1.id = ''
		client2 = Client()
		client2.id = ''
		self.assertFalse(client1 == client2)

	def test_has_contact(self):
		client = Client()
		self.assertFalse(client.has_contact())

		client.address = 'localhost'
		self.assertFalse(client.has_contact())

		client.port = 25001
		self.assertTrue(client.has_contact())
