
import unittest
import datetime as dt
import base64
from lib.mail import Mail, Queue

class MailTestCase(unittest.TestCase):
	def test_mail_str(self):
		mail = Mail()
		mail.uuid = '123'
		mail.receiver = 'receiver'

		self.assertEqual(str(mail), 'Mail(123)')

	def test_dict(self):
		mail1 = Mail()
		mail1.uuid = '123'
		mail1.sender = 'test from'
		mail1.receiver = 'test to'
		mail1.body = 'test body'
		mail1.forwarded_to = ['test3', 'test4']

		self.assertEqual(mail1.as_dict(), mail1.as_dict() | {
			'receiver': 'test from',
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
		})

		mail2 = Mail()
		mail2.from_dict(mail1.as_dict())

		self.assertEqual(mail2.as_dict(), mail1.as_dict() | {
			'receiver': 'test from',
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
		})

	def test_encode(self):
		mail1 = Mail()
		mail1.created_at = dt.datetime(2001, 1, 1, 0, 0, 0, 0)
		mail1.uuid = '123'
		mail1.sender = 'test from'
		mail1.receiver = 'test to'
		mail1.subject = 'test subject'
		mail1.body = 'test body'

		encoded = mail1.encode()
		self.assertEqual(mail1.encode(), 'ARMyMDAxLTAxLTAxVDAwOjAwOjAwEAl0ZXN0IGZyb20RB3Rlc3QgdG8gDHRlc3Qgc3ViamVjdCEJAAAAdGVzdCBib2R5')

		mail2 = Mail()
		mail2.decode(base64.b64decode(encoded))
