
import unittest
from lib.cash import Cash

class CashTestCase(unittest.TestCase):
	def test_str(self):
		cash = Cash('test1', 1)
		self.assertEqual(str(cash), 'Cash(b=1)')

	def test_mine(self):
		cash1 = Cash('test1', 1)
		cycles = cash1.mine()
		self.assertTrue(cycles > 0)
		self.assertTrue(cycles < 10)

	def test_verify(self):
		cash2 = Cash('test1', 24)
		self.assertTrue(cash2.verify('000000b3b274d58f99bc290bf89160b7460e92c8efbb8b049dd66899e92a33b4', 66156319))
