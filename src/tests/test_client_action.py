
import unittest
from lib.client import Action, Client
from lib.overlay import Node

class ClientActionTestCase(unittest.TestCase):
	def test_str(self):
		action = Action('test')
		self.assertEqual(str(action), 'Action(test/None,d=None,s=False)')

		action = Action('test', 'data')
		self.assertEqual(str(action), 'Action(test/data,d=None,s=False)')

		action = Action('test', 33)
		self.assertEqual(str(action), 'Action(test/33,d=None,s=False)')

	def test_eq(self):
		action1 = Action('test')
		action2 = Action('test')
		self.assertEqual(action1, action2)

		action1 = Action('test', 'data')
		action2 = Action('test', 'data')
		self.assertEqual(action1, action2)

		action1 = Action('test', 33)
		action2 = Action('test', 33)
		self.assertEqual(action1, action2)

		action1 = Action('test', 'data')
		action2 = Action('test')
		self.assertNotEqual(action1, action2)

		action1 = Action('test', 33)
		action2 = Action('test', 'data')
		self.assertNotEqual(action1, action2)

		self.assertNotEqual(action1, 1)

	def test_actions(self):
		client = Client()
		client.add_action(Action('test'))
		self.assertEqual(client.get_actions(), [Action('test')])
		self.assertEqual(client.get_actions(), [Action('test')])
		self.assertEqual(client.get_actions(True), [Action('test')])
		self.assertEqual(client.get_actions(), [])

		client.add_action(Action('test1', 'data1'))
		client.add_action(Action('test2'))
		client.add_action(Action('test3', 33))
		self.assertEqual(client.get_actions(), [
			Action('test1', 'data1'),
			Action('test2', None),
			Action('test3', 33),
		])
		self.assertFalse(client.has_action('test3'))

		action2 = client.resolve_action('test2')
		self.assertEqual(action2, Action('test2', None))
		self.assertEqual(client.get_actions(), [
			Action('test1', 'data1'),
			Action('test3', 33),
		])

		self.assertFalse(client.has_action('test4'))
