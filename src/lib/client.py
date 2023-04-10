
import socket
import uuid
import datetime as dt
import hashlib
import base58
import base64

import lib.overlay as overlay

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key

class Client():
	uuid: str # Internal ID
	address: str
	port: int
	id: str
	seen_at: dt.datetime
	meetings: int
	is_bootstrap: bool
	debug_add: str

	# Unmapped
	node: overlay.Node
	sock: socket.socket

	# Connection Mode
	# 0 = DISCONNECTED
	# 1 = CONNECTED
	# 2 = AUTHENTICATED (has sent ID command and received ID command)
	conn_mode: int

	# Directory Mode
	# i = incoming
	# o = outgoing
	dir_mode: str

	# Authenticated (Binary)
	# 0, 0 = 0 (Not Authenticated)
	# 0, 1 = 1 (send ID command)
	# 1, 0 = 2 (received ID command)
	# 1, 1 = 3 (Authenticated both)
	auth: int

	actions: list
	#public_key: bytes

	def __init__(self):
		self.uuid = str(uuid.uuid4())
		# print('-> Client.__init__({})'.format(self.uuid))
		self.address = None
		self.port = None
		self.id = None
		self.seen_at = dt.datetime.strptime('2001-01-01 00:00:00', '%Y-%m-%d %H:%M:%S')
		self.meetings = 0
		self.is_bootstrap = False
		self.debug_add = 'Init'

		# Unmapped
		self.node = None
		self.sock = None
		self.conn_mode = 0
		self.dir_mode = None
		self.auth = 0
		self.actions = []
		self.public_key = None

	def __str__(self):
		return 'Client({},a:p={}:{},ID={},c={},d={},a={},ac={})'.format(self.uuid, self.address, self.port, self.id, self.conn_mode, self.dir_mode, self.auth, len(self.actions))

	def __repr__(self): # pragma: no cover
		return 'Client({})'.format(self.uuid)

	def as_dict(self) -> dict:
		data = dict()
		if self.address != None:
			data['address'] = self.address
		if self.port != None:
			data['port'] = self.port
		if self.id != None:
			data['id'] = self.id
		if self.seen_at != None:
			data['seen_at'] = self.seen_at.isoformat()
		if self.meetings != None:
			data['meetings'] = self.meetings
		if self.is_bootstrap:
			data['is_bootstrap'] = self.is_bootstrap
		if self.debug_add != None:
			data['debug_add'] = self.debug_add

		return data

	def from_dict(self, data: dict):
		# print('-> Client.from_dict({})'.format(self.uuid))

		if 'address' in data:
			self.address = data['address']
		if 'port' in data:
			self.port = int(data['port'])
		if 'id' in data:
			self.set_id(data['id'])
		if 'seen_at' in data:
			self.seen_at = dt.datetime.fromisoformat(data['seen_at'])
		if 'meetings' in data:
			self.meetings = int(data['meetings'])
		if 'is_bootstrap' in data:
			self.is_bootstrap = data['is_bootstrap']
		if 'debug_add' in data:
			self.debug_add = data['debug_add']

	def from_list(self, data: list):
		# print('-> Client.from_list({})'.format(data))
		l = len(data)

		self.id = data[0]

		if l >= 3:
			self.address = data[1]
			self.port = int(data[2])

	def refresh_seen_at(self):
		self.seen_at = dt.datetime.utcnow()

	def inc_meetings(self):
		self.meetings += 1

	def set_id(self, id: str):
		self.id = id
		self.node = overlay.Node.parse(id)

	def distance(self, node: overlay.Node) -> int:
		# print('-> Client.distance()')
		# print('-> self: {}'.format(self))
		# print('-> node: {}'.format(node))

		if self.node == None:
			return overlay.Distance()

		return self.node.distance(node)

	def __eq__(self, other) -> bool:
		if not isinstance(other, Client):
			return False

		if self.id == '' or other.id == '':
			return False

		if self.uuid != None and other.uuid != None and self.uuid == other.uuid:
			return True

		if self.id == None or other.id == None:
			return False

		return self.id == other.id

	def add_action(self, action_id: str, data: list = None):
		self.actions.append([action_id, data])

	def get_actions(self, and_reset: bool = False) -> list:
		if and_reset:
			return self.reset_actions()
		return list(self.actions)

	def remove_action(self, action_id: str):
		found = list(filter(lambda _action: _action[0] == action_id, self.actions))
		if len(found) > 0:
			self.actions.remove(found[0])

	def reset_actions(self) -> list:
		_actions = list(self.actions)
		self.actions = []
		return _actions

	def has_action(self, action_id: str, remove: bool = False) -> bool:
		print('-> Client.has_action({})'.format(action_id))
		found = list(filter(lambda _action: _action[0] == action_id, self.actions))
		print('-> found: {}'.format(found))
		if len(found) > 0:
			item = found[0]
			if remove:
				self.remove_action(action_id)
			return [True, item[1]]
		return [False, None]

	def has_contact(self) -> bool:
		return self.address != None and self.port != None

	def load_public_key_from_pem_file(self, path: str):
		print('-> Client.load_public_key_from_pem_file({})'.format(path))
		with open(path, 'rb') as f:
			key = f.read()

		self.public_key = serialization.load_pem_public_key(key)
		print('-> public key: {}'.format(type(self.public_key)))

	def write_public_key_to_pem_file(self, path: str) -> bool:
		print('-> Client.write_public_key_to_pem_file({})'.format(path))
		if not self.has_public_key():
			return False

		public_key_pkcs1 = self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.PKCS1
		)

		with open(path, 'wb') as f:
			f.write(public_key_pkcs1)

		return True

	def load_public_key_from_base64_der(self, raw: str):
		print('-> Client.load_public_key_from_base64_der({})'.format(raw))
		raw = base64.b64decode(raw)
		self.public_key = serialization.load_der_public_key(raw)

	def get_der_base64_public_key(self) -> str:
		if not self.has_public_key():
			return None

		public_bytes = self.public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)

		return base64.b64encode(public_bytes).decode('utf-8')

	def reset_public_key(self):
		self.public_key = None

	def has_public_key(self) -> bool:
		return self.public_key != None

	def verify_public_key(self) -> bool:
		if not self.has_public_key():
			return False

		public_bytes = self.public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)

		hash_obj = hashlib.new('ripemd160')
		hash_obj.update(public_bytes)

		base58_hash = base58.b58encode(hash_obj.digest()).decode('utf-8')
		return f'FC_{base58_hash}' == self.id

	def reset(self):
		print('-> Client.reset()')
		self.sock = None
		self.conn_mode = 0
		self.dir_mode = None
		self.auth = 0
		self.actions = []
