
import unittest
import datetime as dt
import base64
from lib.helper import password_key_derivation

class PasswordKeyDerivationTestCase(unittest.TestCase):
	def test_pkd1(self):
		password = 'password'
		pkd = password_key_derivation(password.encode())
		self.assertEqual(pkd, 'Ya0zOyDI6bKMS4pBzx1V5L4dphxMIQuFWq7crk2rhX424P9A4EeXhlLwzChxWCY5wR39SWPzfrIaWcHXLB0ZAg==')
