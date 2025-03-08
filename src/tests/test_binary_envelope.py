
from unittest import TestCase
from lib.helper import binary_encode, binary_decode


class BinaryEnvelopeTestCase(TestCase):
	def test_encode1(self):
		data = {
			1: 'ABC1',
			2: 'ABC2',
		}
		expected = b'\x01\x04ABC1\x02\x04ABC2'
		actual = binary_encode(data, 1)
		self.assertEqual(actual, expected)

	def test_encode2(self):
		data = {
			1: 'ABC',
			65: 'DEFG',
			0x65: 'HIJK',
		}
		expected = b'\x01\x03\x00\x00\x00ABCA\x04\x00\x00\x00DEFGe\x04\x00\x00\x00HIJK'
		actual = binary_encode(data, 4)
		self.assertEqual(actual, expected)

	def test_decode1(self):
		data = b'\x01\x04ABC1\x02\x04ABC2'
		expected = {
			1: b'ABC1',
			2: b'ABC2',
		}
		actual = binary_decode(data, 1)
		self.assertEqual(actual, expected)

	def test_decode2(self):
		data = b'\x01\x03\x00\x00\x00ABCA\x04\x00\x00\x00DEFGe\x04\x00\x00\x00HIJK'
		expected = {
			1: b'ABC',
			65: b'DEFG',
			101: b'HIJK',
		}
		actual = binary_decode(data, 4)
		self.assertEqual(actual, expected)
