
import unittest
from lib.helper import generate_id_from_public_key_file, is_valid_uuid, binary_encode, binary_decode

class HelperTestCase(unittest.TestCase):
	def test_generate_id_from_public_key_file(self):
		self.assertEqual(generate_id_from_public_key_file('resources/tests/public_key.pem'), 'FC_5C6EAzLB6gpD6BLYhqFGbV7Cb5MzhD9wB6iwvQw6zhx')

	def test_is_valid_uuid_v4(self):
		self.assertTrue(is_valid_uuid('642b8d3b-7b73-4941-bb11-c6ac13c18ba5'))
		self.assertFalse(is_valid_uuid('xyz'))

	def test_binary_encode(self):
		data = {
			0x01: 'ABC',
			0x02: 'DEF',
		}
		encoded = binary_encode(data, 1)
		self.assertEqual(encoded, b'\x01\x03ABC\x02\x03DEF')

		data = {
			0x01: 'ABC',
			0x02: b'DEF',
		}
		encoded = binary_encode(data, 1)
		self.assertEqual(encoded, b'\x01\x03ABC\x02\x03DEF')


		data = {
			0x01: 'ABC',
			0x02: 'DEF',
		}
		encoded = binary_encode(data, 4)
		self.assertEqual(encoded, b'\x01\x03\x00\x00\x00ABC\x02\x03\x00\x00\x00DEF')


		with self.assertRaises(AttributeError) as context:
			binary_encode({'A': 'ABC'}, 1)
