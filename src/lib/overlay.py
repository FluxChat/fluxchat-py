
import base58

class Node():
	id: str

	def __init__(self, id: str):
		self.id = id

	def __str__(self):
		return 'Node({})'.format(self.id)

	def __repr__(self):
		return 'Node({})'.format(self.id)

	def decode(self) -> bytes:
		return base58.b58decode(self.id[3:])

	def has_valid_id(self) -> bool:
		if self.id[0:3] != 'FC_':
			print('-> Invalid ID')
			return False

		return len(self.decode()) == 20

	def distance(self, other) -> int:
		return Distance(self, other)

	def parse(_id: str):
		_node = Node(_id)
		if not _node.has_valid_id():
			raise ValueError('Invalid ID')

		return _node

class Distance():
	_bytes: bytes
	_distance: int

	def __init__(self, node1: Node, node2: Node):
		id1 = node1.decode()
		id2 = node2.decode()

		# self._distance = 0
		# for a, b in zip(id1, id2):
		# 	bs = bin(a ^ b)[2:].zfill(8).find('1')
		# 	print('-> bs: {}'.format(bs))
		# 	self._distance += bs

		self._distance = sum([bin(a ^ b)[2:].zfill(8).find('1') for a, b in zip(id1, id2)])

	def __str__(self):
		return 'Distance({})'.format(self._distance)

	def __lt__(self, other):
		raise NotImplementedError('Distance.__lt__')

	def __le__(self, other):
		raise NotImplementedError('Distance.__le__')

	def __eq__(self, other):
		if not isinstance(other, Distance):
			return False
		return self._distance == other._distance

	def __ne__(self, other):
		raise NotImplementedError('Distance.__ne__')

	def __gt__(self, other):
		raise NotImplementedError('Distance.__gt__')

	def __ge__(self, other):
		raise NotImplementedError('Distance.__ge__')
