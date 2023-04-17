
import unittest
import datetime as dt
from lib.mail import Message, Queue

class MailTestCase(unittest.TestCase):
	def test_message_str(self):
		message = Message()
		message.uuid = '123'
		message.receiver = 'receiver'

		self.assertEqual(str(message), 'Message(123,r=receiver)')

	def test_message1(self):
		message1 = Message()
		message1.uuid = '123'
		message1.receiver = 'test to'
		message1.body = 'test body'
		message1.forwarded_to = ['test3', 'test4']

		self.assertEqual(message1.as_dict(), message1.as_dict() | {
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
		})

		message2 = Message()
		message2.from_dict(message1.as_dict())

		self.assertEqual(message2.as_dict(), message1.as_dict() | {
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
		})

	def test_message2(self):
		message1 = Message('to', 'body')

		self.assertEqual(message1.receiver, 'to')
		self.assertEqual(message1.body, 'body')
