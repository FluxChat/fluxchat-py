from os import getenv
from base58 import b58decode


class Node():
	pubid: str

	def __init__(self, pubid: str):
		# print(f'-> Node.__init__() {pubid}')
		self.pubid = pubid

	def __str__(self): # pragma: no cover
		return 'Node({})'.format(self.pubid)

	def __repr__(self): # pragma: no cover
		return 'Node({})'.format(self.pubid)

	def __eq__(self, other):
		if isinstance(other, str):
			return self.pubid == other

		if not isinstance(other, Node):
			return False

		return self.pubid == other.pubid

	def decode(self) -> bytes:
		# print(f'-> Node.decode() -> {self.pubid}')
		return b58decode(self.pubid[3:])

	def has_valid_id(self) -> bool:
		if self.pubid[0:3] != 'FC_':
			return False

		return len(self.decode()) == 32

	def distance(self, other):
		return Distance(self, other)

	@staticmethod
	def parse(pubid: str):
		# print(f'-> Node.parse() {pubid}')
		node = Node(pubid)
		if not getenv('IS_UNITTEST') and not node.has_valid_id(): # pragma: no cover
			raise ValueError('Invalid ID')

		return node

class Distance():
	_distance: int

	def __init__(self, node1: Node = None, node2: Node = None):
		self._distance = 256

		if node1 is not None and node2 is not None:
			# print(f'-> node1: {node1}')
			# print(f'-> node2: {node2}')

			id1 = node1.decode()
			id2 = node2.decode()

			for a, b in zip(id1, id2):
				x = a ^ b
				if x == 0:
					self._distance -= 8
				else:
					self._distance -= bin(x)[2:].zfill(8).find('1')
					break

	def __str__(self): # pragma: no cover
		return 'Distance({})'.format(self._distance)

	def __lt__(self, other):
		return self._distance < other._distance

	def __eq__(self, other):
		if isinstance(other, int):
			return self._distance == other

		if not isinstance(other, Distance):
			return False

		return self._distance == other._distance
