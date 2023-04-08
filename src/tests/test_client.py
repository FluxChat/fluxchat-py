
import unittest
from lib.client import Client
from lib.overlay import Node

class ClientTestCase(unittest.TestCase):
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

		self.assertEqual(str(client), 'Client(test,a:p=localhost:25001,ID=FC_test1,c=99,d=t,a=3,ac=4)')

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

	def test_actions(self):
		client = Client()
		client.add_action('test')
		self.assertEqual(client.get_actions(), [['test', None]])
		self.assertEqual(client.get_actions(), [['test', None]])
		self.assertEqual(client.get_actions(True), [['test', None]])
		self.assertEqual(client.get_actions(), [])

		client.add_action('test1', 'data1')
		client.add_action('test2')
		client.add_action('test3', 33)
		self.assertEqual(client.get_actions(), [
			['test1', 'data1'],
			['test2', None],
			['test3', 33],
		])

		client.remove_action('test2')
		self.assertEqual(client.get_actions(), [
			['test1', 'data1'],
			['test3', 33],
		])

		has_a, data = client.has_action('test3')
		self.assertTrue(has_a)
		self.assertEqual(client.get_actions(), [
			['test1', 'data1'],
			['test3', 33],
		])

		has_a, data = client.has_action('test3', True)
		self.assertTrue(has_a)
		self.assertEqual(data, 33)
		self.assertEqual(client.get_actions(), [['test1', 'data1']])

		has_a, data = client.has_action('test4', True)
		self.assertFalse(has_a)
		self.assertEqual(data, None)

	def test_has_contact(self):
		client = Client()
		self.assertFalse(client.has_contact())

		client.address = 'localhost'
		self.assertFalse(client.has_contact())

		client.port = 25001
		self.assertTrue(client.has_contact())
