
import datetime as dt
from socket import socket as Socket
from uuid import uuid4
from base64 import b64encode, b64decode

from lib.cash import Cash
from lib.overlay import Node, Distance
from lib.helper import generate_id_from_public_key_rsa

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Action():
	id: str
	subid: str
	is_strong: bool # Strong actions are not removed from the queue on soft_reset_actions()
	valid_until: dt.datetime

	def __init__(self, id: str, subid: str = None, data = None):
		self.id = id
		self.subid = subid
		self.data = data
		self.is_strong = False
		self.func = None
		self.valid_until = None

	def __str__(self): # pragma: no cover
		return 'Action({}/{},d={},s={})'.format(self.id, self.subid, self.data, self.is_strong)

	def __repr__(self): # pragma: no cover
		return 'Action({}/{})'.format(self.id, self.subid)

	def __eq__(self, other) -> bool:
		if not isinstance(other, Action):
			return False

		if self.id == other.id and self.subid == other.subid:
			return True

		return False


class Challenge():
	min: int
	max: int
	data: str
	proof: str
	nonce: str


class Client():
	uuid: int # Internal ID
	pubid: str # Public ID aka Short Public Keyy
	address: str
	port: int
	seen_at: dt.datetime
	meetings: int
	is_bootstrap: bool
	is_trusted: bool
	debug_add: str
	# _is_new: bool
	_changed: bool

	# Unmapped
	node: Node
	sock: Socket
	# buf: bytes

	# Connection Mode
	# 0 = DISCONNECTED
	# 1 = CONNECTED
	# 2 = AUTHENTICATED (has sent ID command and received ID command)
	conn_mode: int
	conn_msg: str

	# Directory Mode
	# i = incoming
	# o = outgoing
	dir_mode: str

	# Authenticated (Binary)
	# 0, 0, 0, 0 = 0 (Not Authenticated)
	# 0, 0, 0, 1 = 1 (sent CHALLENGE command)
	# 0, 0, 1, 0 = 2 (received CHALLENGE command)
	# 0, 1, 0, 0 = 4 (sent ID command)
	# 1, 0, 0, 0 = 8 (received ID command)
	# 1, 1, 1, 1 = 15 (Authenticated both)
	auth: int

	actions: list[Action]
	cash: Cash
	challenge: Challenge

	def __init__(self):
		self.uuid = None
		self.pubid = None
		self.address = None
		self.port = None
		self.created_at = dt.datetime.now(dt.UTC)
		self.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')
		self.used_at = dt.datetime.now(dt.UTC)
		self.meetings = 0
		self.is_bootstrap = False
		self.is_trusted = False
		self.debug_add = 'Init'
		# self._is_new = True
		self._changed = True

		# Unmapped
		self.node = None
		self.sock = None
		self.conn_mode = 0
		self.conn_msg = 'Init'
		self.dir_mode = None
		self.auth = 0
		self.actions = list()
		self.public_key = None
		self.cash = None

		self.challenge = Challenge()

	def __str__(self):
		return 'Client({},{}:{},PID={},c={},d={},a={},ac={})'.format(self.uuid, self.address, self.port, self.pubid, self.conn_mode, self.dir_mode, self.auth, len(self.actions))

	def __repr__(self): # pragma: no cover
		return 'Client({})'.format(self.uuid)

	def __eq__(self, other) -> bool:
		if not isinstance(other, Client):
			return False

		if self.pubid == '' or other.pubid == '':
			return False

		if self.uuid is not None and other.uuid is not None and self.uuid == other.uuid:
			return True

		if self.pubid is None or other.pubid is None:
			return False

		return self.pubid == other.pubid

	# def set_is_new(self, value: bool = True) -> bool:
	# 	self._is_new = value

	# @property
	# def is_new(self) -> bool:
	# 	return self._is_new

	def changed(self, value: bool = True) -> None:
		self._changed = value

	@property
	def has_changed(self) -> bool:
		return self._changed

	def as_dict(self) -> dict:
		data = dict()
		if self.address is not None:
			data['address'] = self.address
		if self.port is not None:
			data['port'] = self.port
		if self.pubid is not None:
			data['pubid'] = self.pubid
		if self.created_at is not None:
			data['created_at'] = self.created_at.isoformat()
		if self.seen_at is not None:
			data['seen_at'] = self.seen_at.isoformat()
		if self.used_at is not None:
			data['used_at'] = self.used_at.isoformat()
		if self.meetings is not None:
			data['meetings'] = self.meetings
		if self.is_bootstrap:
			data['is_bootstrap'] = self.is_bootstrap
		if self.is_trusted:
			data['is_trusted'] = self.is_trusted
		if self.debug_add is not None:
			data['debug_add'] = self.debug_add

		return data

	def from_dict(self, data: dict):
		if 'address' in data:
			self.address = data['address']
		if 'port' in data:
			self.port = int(data['port'])
		if 'pubid' in data:
			self.set_pubid(data['pubid'])
		if 'created_at' in data:
			self.created_at = dt.datetime.fromisoformat(data['created_at'])
		if 'seen_at' in data:
			self.seen_at = dt.datetime.fromisoformat(data['seen_at'])
		if 'used_at' in data:
			self.used_at = dt.datetime.fromisoformat(data['used_at'])
		if 'meetings' in data:
			self.meetings = int(data['meetings'])
		if 'is_bootstrap' in data:
			self.is_bootstrap = data['is_bootstrap']
		if 'is_trusted' in data:
			self.is_trusted = data['is_trusted']
		if 'debug_add' in data:
			self.debug_add = data['debug_add']

	def from_list(self, data: list):
		print(f'-> from_list: {data}')
		self.pubid = data[0]

		if len(data) >= 3:
			self.address = data[1]
			self.port = int(data[2])

	@staticmethod
	def from_db(node: tuple) -> 'Client':
		uuid, pubid, address, port, created_at, seen_at, used_at, meetings, is_bootstrap, is_trusted, debug_add = node
		print(f'-> from_db: {node}')

		client = Client()
		client.uuid = uuid
		client.pubid = pubid
		client.address = address
		client.port = port
		client.created_at = dt.datetime.fromisoformat(created_at)
		client.seen_at = dt.datetime.fromisoformat(seen_at)
		client.used_at = dt.datetime.fromisoformat(used_at)
		client.meetings = meetings
		client.is_bootstrap = is_bootstrap
		client.is_trusted = is_trusted
		client.debug_add = debug_add
		client.set_pubid(pubid)

		return client


	def refresh_seen_at(self) -> None:
		self.seen_at = dt.datetime.now(dt.UTC)

	def refresh_used_at(self) -> None:
		self.used_at = dt.datetime.now(dt.UTC)

	def inc_meetings(self) -> None:
		self.meetings += 1

	def set_pubid(self, pubid: str) -> None:
		print(f'-> set_pubid: {pubid}')
		self.pubid = pubid
		self.node = Node.parse(pubid)

	def distance(self, node: Node) -> int:
		if self.node is None:
			return Distance()

		return self.node.distance(node)

	def add_action(self, action: Action):
		self.actions.append(action)

	def get_actions(self, soft_reset: bool = False) -> list[Action]:
		_actions = list(self.actions)
		if soft_reset:
			self.soft_reset_actions()
		return _actions

	# Remove actions with is_strong == False
	def soft_reset_actions(self) -> list[Action]:
		strong_actions = list(filter(lambda _action: _action.is_strong, self.actions))
		actions = list(self.actions)
		self.actions = strong_actions
		return actions

	def has_action(self, aid: str, subid: str = None) -> bool:
		def ffunc(_action):
			return _action.id == aid and _action.subid == subid
		found = list(filter(ffunc, self.actions))
		return len(found) > 0

	# Search for action by id and subid and remove it from actions list.
	# Keep Strong actions.
	# Force remove will also remove strong actions.
	def resolve_action(self, aid: str, subid: str = None, force_remove: bool = False) -> Action:
		def ffunc(_action):
			return _action.id == aid and _action.subid == subid
		found = list(filter(ffunc, self.actions))
		if len(found) > 0:
			if not found[0].is_strong or force_remove:
				self.actions.remove(found[0])
			return found[0]
		return None

	def remove_action(self, action: Action) -> None:
		self.actions.remove(action)

	def has_contact(self) -> bool:
		return self.address is not None and self.port is not None

	def load_public_key_from_pem_file(self, path: str) -> None:
		with open(path, 'rb') as f:
			key = f.read()

		self.public_key = serialization.load_pem_public_key(key)

	def write_public_key_to_pem_file(self, path: str) -> bool:
		if not self.has_public_key():
			return False

		# PEM is used to store public keys in Base64 encoded format, with header and footer.
		public_key_pem = self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat. SubjectPublicKeyInfo
		)

		with open(path, 'wb') as f:
			f.write(public_key_pem)

		return True

	def load_public_key_from_pem(self, raw: str) -> None:
		print(f'-> load_public_key_from_pem: {raw}')
		der_key = b64decode(raw)
		# self.public_key = serialization.load_pem_public_key(raw)
		self.public_key = serialization.load_der_public_key(der_key)

	def get_base64_public_key(self) -> str:
		if not self.has_public_key():
			return None

		# DER is binary representation of public key.
		public_bin = self.public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		return b64encode(public_bin).decode()

	def reset_public_key(self) -> None:
		self.public_key = None

	def has_public_key(self) -> bool:
		return self.public_key is not None

	def verify_public_key(self) -> bool:
		if not self.has_public_key():
			return False

		return generate_id_from_public_key_rsa(self.public_key) == self.pubid

	def encrypt(self, data: bytes) -> bytes:
		if not self.has_public_key():
			return None

		return self.public_key.encrypt(
			data,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)

	def reset(self) -> None:
		self.sock = None
		self.conn_mode = 0
		self.dir_mode = None
		self.auth = 0
		self.actions = []
		self.challenge = Challenge()
