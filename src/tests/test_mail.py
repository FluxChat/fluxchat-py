
from unittest import TestCase
import datetime as dt
import base64
from lib.mail import Mail

class MailTestCase(TestCase):
	def test_mail_str(self):
		mail = Mail()
		mail.pubid = '123'
		mail.receiver = 'receiver'

		self.assertEqual(str(mail), 'Mail(123)')

	def test_dict(self):
		mail1 = Mail()
		mail1.pubid = '123'
		mail1.sender = 'test from'
		mail1.receiver = 'test to'
		mail1.body = 'test body'
		mail1.forwarded_to = ['test3', 'test4']

		d1 = mail1.as_dict()
		del d1['created_at']
		self.assertEqual(d1, {
			'sender': 'test from',
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
			'is_encrypted': False,
		})

		mail2 = Mail()
		mail2.from_dict(mail1.as_dict())

		d2 = mail2.as_dict()
		del d2['created_at']
		self.assertEqual(d2, {
			'sender': 'test from',
			'receiver': 'test to',
			'body': 'test body',
			'forwarded_to': ['test3', 'test4'],
			'is_encrypted': False,
		})

	# def test_encode(self):
	# 	mail1 = Mail()
	# 	mail1.created_at = dt.datetime(2001, 1, 1, 0, 0, 0, 0)
	# 	mail1.pubid = '123'
	# 	mail1.sender = 'test from'
	# 	mail1.receiver = 'test to'
	# 	mail1.subject = 'test subject'
	# 	mail1.body = 'test body'

	# 	encoded = mail1.encode()
	# 	self.assertEqual(mail1.encode(), 'ARMyMDAxLTAxLTAxVDAwOjAwOjAwEAl0ZXN0IGZyb20RB3Rlc3QgdG8gDHRlc3Qgc3ViamVjdCEJAAAAdGVzdCBib2R5')

	# 	mail2 = Mail()
	# 	mail2.decode(base64.b64decode(encoded))
