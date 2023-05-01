
import unittest
import datetime as dt
from lib.mail import Mail, Queue

class MailTestCase(unittest.TestCase):
	def test_mail_str(self):
		mail = Mail()
		mail.uuid = '123'
		mail.receiver = 'receiver'

		self.assertEqual(str(mail), 'Mail(123)')

	def test_mail1(self):
		mail1 = Mail()
		mail1.uuid = '123'
		mail1.receiver = 'test to'
		mail1.body = 'test body'
		mail1.forwarded_to = ['test3', 'test4']

		self.assertEqual(mail1.as_dict(), mail1.as_dict() | {
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
		})

		mail2 = Mail()
		mail2.from_dict(mail1.as_dict())

		self.assertEqual(mail2.as_dict(), mail1.as_dict() | {
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
		})
