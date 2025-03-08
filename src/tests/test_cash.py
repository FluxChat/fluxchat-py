
from unittest import TestCase
from lib.cash import Cash


class CashTestCase(TestCase):
	def test_str(self):
		cash = Cash('test1', 1)
		self.assertEqual(str(cash), 'Cash(b=1)')

	def test_mine(self):
		cash = Cash('test1', 1)
		cycles = cash.mine()
		self.assertTrue(cycles > 0)
		self.assertTrue(cycles < 10)

	def test_verify1a(self):
		cash = Cash('test1', 24)
		self.assertTrue(cash.verify('000000b3b274d58f99bc290bf89160b7460e92c8efbb8b049dd66899e92a33b4', 66156319))

	def test_verify2(self):
		cash = Cash('test1', 10)
		self.assertFalse(cash.verify('0000004388017c0c014e79067c32585f6bfa11be3a7b525f2512529c773ecf61', 58067403))

	def test_verify3(self):
		cash = Cash('test1', 20)
		self.assertFalse(cash.verify('236ec5266d857b1372618e86eeb33c9850a01f73ea767ff5e656650cb11d555a', 1234))

	def test_verify4(self):
		cash = Cash('test1', 20)
		self.assertFalse(cash.verify('xyz', 1234))
