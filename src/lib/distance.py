
import base58
from lib.node import Node

class Distance():
	_bytes: bytes

	def __init__(self, id1: Node, id2: Node):
		id1 = id1.decode()
		id2 = id2.decode()

		self._bytes = bytes([a ^ b for a, b in zip(id1, id2)])

	def __str__(self):
		return self._bytes.hex()

	def __lt__(self, other):
		pass

	def __le__(self, other):
		pass

	def __eq__(self, other):
		if not isinstance(other, Distance):
			return False
		return self._bytes == other._bytes

	def __ne__(self, other):
		pass

	def __gt__(self, other):
		pass

	def __ge__(self, other):
		pass
