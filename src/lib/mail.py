
import datetime as dt
from base64 import b64encode
from json import loads
from uuid import uuid4
from logging import getLogger
from lib.overlay import Node
from lib.helper import binary_encode, binary_decode


class Mail():
	uuid: int
	pubid: str
	sender: str
	receiver: str
	origin: Node
	target: Node
	subject: str
	body: str
	created_at: dt.datetime
	received_at: dt.datetime
	valid_until: dt.datetime
	forwarded_to: list
	is_encrypted: bool
	is_delivered: bool
	is_new: bool
	verified: str
	sign_hash: str
	sign: str
	_changes: bool

	def __init__(self, pubid_s: str = None):
		if pubid_s is None:
			self.pubid = str(uuid4())
		else:
			self.pubid = pubid_s
		self.sender = None
		self.receiver = None
		self.origin = None
		self.target = None
		self.subject = None
		self.body = None
		self.created_at = dt.datetime.now(dt.UTC)
		self.received_at = None
		self.valid_until = None
		self.forwarded_to = []
		self.is_encrypted = False
		self.is_delivered = None
		self.is_new = None
		self.verified = None
		self.sign_hash = None
		self.sign = None
		self._changes = False

		self._logger = getLogger('app.mail')

	def __str__(self): # pragma: no cover
		return 'Mail({})'.format(self.pubid)

	def __repr__(self): # pragma: no cover
		return self.__str__()

	def changed(self, value: bool = True):
		self._changes = value

	def as_dict(self) -> dict:
		# self._logger.debug('as_dict()')

		data = dict()
		if self.sender is not None:
			data['sender'] = self.sender
		if self.receiver is not None:
			data['receiver'] = self.receiver
		if self.subject is not None:
			data['subject'] = self.subject
		if self.body is not None:
			data['body'] = self.body
		if self.created_at is not None:
			data['created_at'] = self.created_at.isoformat()
		if self.received_at is not None:
			data['received_at'] = self.received_at.isoformat()
		if self.valid_until is not None:
			data['valid_until'] = self.valid_until.isoformat()
		if self.forwarded_to is not None and len(self.forwarded_to) > 0:
			data['forwarded_to'] = self.forwarded_to
		if self.is_encrypted is not None:
			data['is_encrypted'] = self.is_encrypted
		if self.is_delivered is not None:
			data['is_delivered'] = self.is_delivered
		if self.is_new is not None:
			data['is_new'] = self.is_new
		if self.verified is not None:
			data['verified'] = self.verified
		if self.sign_hash is not None:
			data['sign_hash'] = self.sign_hash
		if self.sign is not None:
			data['sign'] = self.sign
		return data

	def from_dict(self, data: dict):
		self._logger.debug('from_dict() -> %s', data)

		if 'sender' in data:
			self.set_sender(data['sender'])
		if 'receiver' in data:
			self.set_receiver(data['receiver'])

		if 'subject' in data:
			self.subject = data['subject']
		if 'body' in data:
			self.body = data['body']
		if 'created_at' in data:
			self.created_at = dt.datetime.fromisoformat(data['created_at'])
		if 'received_at' in data:
			self.received_at = dt.datetime.fromisoformat(data['received_at'])
		if 'valid_until' in data:
			self.valid_until = dt.datetime.fromisoformat(data['valid_until'])
		if 'forwarded_to' in data:
			self.forwarded_to = data['forwarded_to']
		if 'is_encrypted' in data:
			self.is_encrypted = data['is_encrypted']
		if 'is_delivered' in data:
			self.is_delivered = data['is_delivered']
		if 'is_new' in data:
			self.is_new = bool(data['is_new'])
		if 'verified' in data:
			self.verified = data['verified']
		if 'sign_hash' in data:
			self.sign_hash = data['sign_hash']
		if 'sign' in data:
			self.sign = data['sign']

	@staticmethod
	def from_queue_db(data: tuple) -> 'Mail':
		print(f'from_db() -> {data}', )
		uuid, pubid, receiver, body, is_encrypted, created_at, valid_until = data

		mail = Mail(pubid)
		mail.uuid = uuid
		mail.set_receiver(receiver)
		mail.body = body
		mail.is_encrypted = is_encrypted
		mail.created_at = dt.datetime.fromisoformat(created_at)
		mail.valid_until = dt.datetime.fromisoformat(valid_until)

		return mail

	@staticmethod
	def from_mail_db(data: tuple) -> 'Mail':
		print(f'from_db() -> {data}', )
		uuid, pubid, sender, receiver, subject, body, forwarded_to, is_encrypted, is_delivered, is_new, verified, sign_hash, sign, created_at, received_at, valid_until = data

		mail = Mail(pubid)
		mail.uuid = uuid
		mail.set_sender(sender)
		mail.set_receiver(receiver)
		mail.subject = subject
		mail.body = body
		mail.forwarded_to = loads(forwarded_to)
		mail.is_encrypted = is_encrypted
		mail.is_delivered = is_delivered
		mail.is_new = is_new
		mail.verified = verified
		mail.sign_hash = sign_hash
		mail.sign = sign
		mail.created_at = dt.datetime.fromisoformat(created_at)
		mail.received_at = dt.datetime.fromisoformat(received_at)
		mail.valid_until = dt.datetime.fromisoformat(valid_until)

		return mail

	def received_now(self):
		self.received_at = dt.datetime.now(dt.UTC)

	def set_sender(self, sender: str):
		try:
			self.origin = Node.parse(sender)
		except:
			self.origin = None
			self.sender = None
		else:
			self.sender = sender

	def set_receiver(self, receiver: str):
		try:
			self.target = Node.parse(receiver)
		except:
			self.target = None
			self.receiver = None
		else:
			self.receiver = receiver

	def encode(self) -> str:
		self._logger.debug('encode()')

		# uuid_len = len(self.pubid).to_bytes(1, 'little')
		sender_len = len(self.sender).to_bytes(1, 'little')
		receiver_len = len(self.receiver).to_bytes(1, 'little')
		subject_len = len(self.subject).to_bytes(1, 'little')
		body_len = len(self.body).to_bytes(4, 'little')
		items = [
			# b'\x00', uuid_len, self.pubid.encode(),
			b'\x01\x13', self.created_at.strftime('%FT%T').encode(),
			b'\x10', sender_len, self.sender.encode(),
			b'\x11', receiver_len, self.receiver.encode(),
			b'\x20', subject_len, self.subject.encode(),
			b'\x21', body_len, self.body.encode(),
		]
		raw = b''.join(items)
		return b64encode(raw).decode()

	def decode(self, data: bytes):
		self._logger.debug('decode(%s)', data)
		# print('data', data)

		data_len = len(data)

		pos = 0
		while pos < data_len:
			item_t = int.from_bytes(data[pos:pos+1], 'little')
			pos += 1

			# if item_t == 0x00:
			if item_t == 0x01:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode()
				self.created_at = dt.datetime.fromisoformat(val)

			elif item_t == 0x10:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode()
				self.set_sender(val)

			elif item_t == 0x11:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode()
				self.set_receiver(val)

			elif item_t == 0x20:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode()
				self.subject = val

			elif item_t == 0x21:
				item_l = int.from_bytes(data[pos:pos+4], 'little')
				pos += 4
				self._logger.debug('body length: %d', item_l)

				val = data[pos:pos+item_l].decode()
				self._logger.debug('body: "%s"', val)

				self.body = val

			else:
				self._logger.warning('unknown type: %s', item_t)
				val = None
				item_l = 0

			pos += item_l

			self._logger.debug('type=%s(%s), length=%d(%s), value=%s(%s)', item_t, type(item_t), item_l, type(item_l), val, type(val))

	def ipc_encode(self) -> bytes:
		self._logger.debug('ipc_encode()')

		data = {}
		if self.pubid is not None:
			data[0x00] = self.pubid
		if self.created_at is not None:
			data[0x01] = self.created_at.strftime('%FT%T')
		if self.received_at is not None:
			data[0x02] = self.received_at.strftime('%FT%T')
		if self.valid_until is not None:
			data[0x03] = self.valid_until.strftime('%FT%T')
		if self.verified is not None:
			data[0x10] = self.verified
		if self.sender is not None:
			data[0x20] = self.sender
		if self.receiver is not None:
			data[0x21] = self.receiver
		if self.subject is not None:
			data[0x30] = self.subject
		if self.body is not None:
			data[0x31] = self.body

		self._logger.debug('data: %s', data)

		return binary_encode(data)

	def ipc_decode(self, raw):
		self._logger.debug('ipc_decode()')
		self._logger.debug('raw: %s "%s"', type(raw), raw)

		data = binary_decode(raw)

		self._logger.debug('data: %s %s', type(data), data)

		if 0x00 in data:
			self.pubid = data[0x00].decode()
		if 0x01 in data:
			item = data[0x01].decode()
			self.created_at = dt.datetime.fromisoformat(item)
		if 0x02 in data:
			item = data[0x02].decode()
			self.received_at = dt.datetime.fromisoformat(item)
		if 0x03 in data:
			item = data[0x03].decode()
			self.valid_until = dt.datetime.fromisoformat(item)
		if 0x10 in data:
			self.verified = data[0x10].decode()
		if 0x20 in data:
			self.sender = data[0x20].decode()
		if 0x21 in data:
			self.receiver = data[0x21].decode()
		if 0x30 in data:
			self.subject = data[0x30].decode()
		if 0x31 in data:
			self.body = data[0x31].decode()

