
import logging
import datetime as dt
import uuid
import base64

import lib.overlay as overlay
from lib.helper import read_json_file, write_json_file

class Mail():
	uuid: str
	sender: str
	receiver: str
	origin: overlay.Node
	target: overlay.Node
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

	def __init__(self):
		self.uuid = str(uuid.uuid4())
		self.sender = None
		self.receiver = None
		self.origin = None
		self.target = None
		self.subject = None
		self.body = None
		self.created_at = dt.datetime.utcnow()
		self.received_at = None
		self.valid_until = None
		self.forwarded_to = []
		self.is_encrypted = False
		self.is_delivered = None
		self.is_new = None
		self.verified = None
		self.sign_hash = None
		self.sign = None

		self._logger = logging.getLogger('mail')
		self._logger.info('init()')

	def __str__(self):
		return 'Mail({})'.format(self.uuid)

	def __repr__(self):
		return self.__str__()

	def as_dict(self) -> dict:
		self._logger.debug('as_dict()')

		data = dict()
		if self.sender != None:
			data['sender'] = self.sender
		if self.receiver != None:
			data['receiver'] = self.receiver
		if self.subject != None:
			data['subject'] = self.subject
		if self.body != None:
			data['body'] = self.body
		if self.created_at != None:
			data['created_at'] = self.created_at.isoformat()
		if self.received_at != None:
			data['received_at'] = self.received_at.isoformat()
		if self.valid_until != None:
			data['valid_until'] = self.valid_until.isoformat()
		if self.forwarded_to != None and len(self.forwarded_to) > 0:
			data['forwarded_to'] = self.forwarded_to
		if self.is_encrypted != None:
			data['is_encrypted'] = self.is_encrypted
		if self.is_delivered != None:
			data['is_delivered'] = self.is_delivered
		if self.is_new != None:
			data['is_new'] = self.is_new
		if self.verified != None:
			data['verified'] = self.verified
		if self.sign_hash != None:
			data['sign_hash'] = self.sign_hash
		if self.sign != None:
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

	def received_now(self):
		self._logger.debug('received_now()')

		self.received_at = dt.datetime.utcnow()

	def set_sender(self, sender: str):
		self._logger.debug('set_sender(%s)', sender)

		try:
			self.origin = overlay.Node.parse(sender)
		except:
			self.origin = None
			self.sender = None
		else:
			self.sender = sender

	def set_receiver(self, receiver: str):
		self._logger.debug('set_receiver(%s)', receiver)

		try:
			self.target = overlay.Node.parse(receiver)
		except:
			self.target = None
			self.receiver = None
		else:
			self.receiver = receiver

	def encode(self) -> str:
		self._logger.debug('encode()')

		# uuid_len = len(self.uuid).to_bytes(1, 'little')
		sender_len = len(self.sender).to_bytes(1, 'little')
		receiver_len = len(self.receiver).to_bytes(1, 'little')
		subject_len = len(self.subject).to_bytes(1, 'little')
		body_len = len(self.body).to_bytes(4, 'little')
		items = [
			# b'\x00', uuid_len, self.uuid.encode('utf-8'),
			b'\x01\x13', self.created_at.strftime('%FT%T').encode('utf-8'),
			b'\x10', sender_len, self.sender.encode('utf-8'),
			b'\x11', receiver_len, self.receiver.encode('utf-8'),
			b'\x20', subject_len, self.subject.encode('utf-8'),
			b'\x21', body_len, self.body.encode('utf-8'),
		]
		raw = b''.join(items)
		return base64.b64encode(raw).decode('utf-8')

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
				val = data[pos:pos+item_l].decode('utf-8')
				self.created_at = dt.datetime.fromisoformat(val)

			elif item_t == 0x10:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode('utf-8')
				self.set_sender(val)

			elif item_t == 0x11:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode('utf-8')
				self.set_receiver(val)

			elif item_t == 0x20:
				item_l = int.from_bytes(data[pos:pos+1], 'little')
				pos += 1
				val = data[pos:pos+item_l].decode('utf-8')
				self.subject = val

			elif item_t == 0x21:
				item_l = int.from_bytes(data[pos:pos+4], 'little')
				pos += 4
				self._logger.debug('body length: %d', item_l)

				val = data[pos:pos+item_l].decode('utf-8')
				self._logger.debug('body: "%s"', val)

				self.body = val

			# elif item_t == 0x30:
			# 	self._logger.debug('decode sign')

			# 	item_l = int.from_bytes(data[pos:pos+2], 'little')
			# 	pos += 2
			# 	self._logger.debug('sign length: %d', item_l)

			# 	val = data[pos:pos+item_l]
			# 	self._logger.debug('sign bytes: "%s"', val)

			# 	self.sign = base64.b64encode(val).decode('utf-8')
			# 	self._logger.debug('sign base64: "%s"', self.sign)

			else:
				self._logger.warning('unknown type: %s', item_t)
				val = None
				item_l = 0

			pos += item_l

			self._logger.debug('type=%s(%s), length=%d(%s), value=%s(%s)', item_t, type(item_t), item_l, type(item_l), val, type(val))

class Queue():
	_path: str
	_config: dict
	_mail_config: dict
	_mails_by_uuid: dict
	_changes: bool
	_retention_time: dt.timedelta

	def __init__(self, path: str, config: dict = None):
		self._path = path
		self._config = config
		self._mail_config = self._config['mail']
		self._mails_by_uuid = dict()
		self._changes = False

		self._retention_time = dt.timedelta(hours=self._mail_config['retention_time'])

		self._logger = logging.getLogger('mail.Queue')
		self._logger.info('init()')

	def load(self):
		self._logger.info('load')

		_data = read_json_file(self._path, {})
		for m_uuid, row in _data.items():
			mail = Mail()
			mail.uuid = m_uuid
			mail.from_dict(row)

			self._logger.debug('load mail: %s', mail)

			self._mails_by_uuid[m_uuid] = mail

	def save(self) -> bool:
		self._logger.info('save() changes=%s', self._changes)

		if not self._changes:
			return False

		_data = dict()
		for mail_uuid, mail in self._mails_by_uuid.items():
			_data[mail_uuid] = mail.as_dict()

		write_json_file(self._path, _data)
		self._changes = False

		return True

	def add_mail(self, mail: Mail):
		self._logger.debug('add_mail(%s)', mail)

		mail.valid_until = dt.datetime.utcnow() + self._retention_time

		self._mails_by_uuid[mail.uuid] = mail
		self._changes = True

	def get_mails(self) -> dict:
		return self._mails_by_uuid.items()

	def has_mail(self, mail_uuid: str) -> bool:
		self._logger.debug('has_mail(%s)', mail_uuid)
		return mail_uuid in self._mails_by_uuid

	def changed(self):
		self._changes = True

	def clean_up(self):
		self._logger.info('clean up')

		remove_mails = []

		ffunc = lambda _mail: _mail[1].valid_until != None and dt.datetime.utcnow() >= _mail[1].valid_until
		old_mails = list(filter(ffunc, self._mails_by_uuid.items()))
		self._logger.debug('old mails A: %s', old_mails)
		remove_mails += old_mails

		for mail_uuid, mail in remove_mails:
			self._logger.debug('remove mail: %s', mail)

			del self._mails_by_uuid[mail_uuid]
			self._changes = True

class Database():
	_path: str
	_data: dict
	_changes: bool

	def __init__(self, path: str) -> None:
		self._path = path
		self._data = dict()
		self._changes = False

		self._logger = logging.getLogger('mail.Database')
		self._logger.info('init()')

	def load(self):
		self._logger.info('load()')

		data = read_json_file(self._path, {})
		for mail_uuid, mail_raw in data.items():
			mail = Mail()
			mail.from_dict(mail_raw)

			self._logger.debug('load mail: %s', mail)

			self._data[mail_uuid] = mail

	def save(self):
		self._logger.info('save() changes=%s', self._changes)

		if not self._changes:
			return

		data = dict()
		for mail_uuid, mail in self._data.items():
			data[mail_uuid] = mail.as_dict()

		write_json_file(self._path, data)
		self._changes = False

	def changed(self):
		self._changes = True

	def add_mail(self, mail: Mail):
		self._logger.debug('add_mail %s', mail)

		self._data[mail.uuid] = mail
		self._changes = True

	def has_mail(self, mail_uuid: str) -> bool:
		self._logger.debug('has_mail %s', mail_uuid)
		return mail_uuid in self._data

	def get_mails(self) -> dict:
		return self._data.items()
