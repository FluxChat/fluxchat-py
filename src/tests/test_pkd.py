
import unittest
import datetime as dt
import base64
from lib.helper import password_key_derivation

class PasswordKeyDerivationTestCase(unittest.TestCase):
	def test_pkd1(self):
		password = 'password'
		pkd = password_key_derivation(password.encode())
		self.assertEqual(pkd.hex(), '61ad333b20c8e9b28c4b8a41cf1d55e4be1da61c4c210b855aaedcae4dab857e36e0ff40e047978652f0cc2871582639c11dfd4963f37eb21a59c1d72c1d1902')
