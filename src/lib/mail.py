
import logging
import datetime as dt
import uuid
import base64

import lib.overlay as overlay
from lib.helper import read_json_file, write_json_file

class Message():
	uuid: str
	sender: str
	receiver: str
	target: overlay.Node
	subject: str
	body: str
	created_at: dt.datetime
	received_at: dt.datetime
	forwarded_to: list
	is_encrypted: bool
	is_delivered: bool

	def __init__(self, receiver: str = None, body: str = None):
		self.uuid = str(uuid.uuid4())
		self.sender = None
		self.receiver = receiver
		self.subject = None
		self.body = body
		self.created_at = dt.datetime.utcnow()
		self.received_at = None
		self.forwarded_to = []
		self.is_encrypted = False
		self.is_delivered = None

		if self.receiver == None:
			self.target = None
		else:
			try:
				self.target = overlay.Node.parse(self.receiver)
			except:
				self.target = None

	def __str__(self):
		return 'Message({},t={})'.format(self.uuid, self.receiver)

	def __repr__(self):
		return self.__str__()

	def as_dict(self) -> dict:
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
		if self.forwarded_to != None and len(self.forwarded_to) > 0:
			data['forwarded_to'] = self.forwarded_to
		if self.is_encrypted != None:
			data['is_encrypted'] = self.is_encrypted
		if self.is_delivered != None:
			data['is_delivered'] = self.is_delivered
		return data

	def from_dict(self, data: dict):
		if 'to' in data: # deprecated # TODO remove
			self.receiver = data['to']
			try:
				self.target = overlay.Node.parse(self.receiver)
			except:
				self.target = None
		if 'receiver' in data:
			self.receiver = data['receiver']
			try:
				self.target = overlay.Node.parse(self.receiver)
			except:
				self.target = None
		if 'sender' in data:
			self.sender = data['sender']
		if 'subject' in data:
			self.subject = data['subject']
		if 'body' in data:
			self.body = data['body']
		if 'created_at' in data:
			self.created_at = dt.datetime.fromisoformat(data['created_at'])
		if 'received_at' in data:
			self.received_at = dt.datetime.fromisoformat(data['received_at'])
		if 'forwarded_to' in data:
			self.forwarded_to = data['forwarded_to']
		if 'is_encrypted' in data:
			self.is_encrypted = data['is_encrypted']
		if 'is_delivered' in data:
			self.is_delivered = data['is_delivered']

	def encode(self) -> str:
		sender_len = len(self.sender)
		receiver_len = len(self.receiver)
		subject_len = len(self.subject)
		body_len = len(self.body)
		items = [
			b'\x00\x13', dt.datetime.utcnow().strftime('%F %T').encode('utf-8'),
			b'\x10', sender_len.to_bytes(1, 'little'), self.sender.encode('utf-8'),
			b'\x11', receiver_len.to_bytes(1, 'little'), self.receiver.encode('utf-8'),
			b'\x21', subject_len.to_bytes(1, 'little'), self.subject.encode('utf-8'),
			b'\x22', body_len.to_bytes(4, 'little'), self.body.encode('utf-8'),
		]
		raw = b''.join(items)
		return base64.b64encode(raw).decode('utf-8')

class Queue():
	_path: str
	_config: dict
	_mail_config: dict
	_messages_by_uuid: dict
	_changes: bool
	_message_retention_time: dt.timedelta

	def __init__(self, path: str, config: dict = None):
		self._path = path
		self._config = config
		self._mail_config = self._config['mail']
		self._messages_by_uuid = dict()
		self._changes = False

		self._message_retention_time = dt.timedelta(hours=self._mail_config['message_retention_time'])

		self._logger = logging.getLogger('mail.Queue')
		self._logger.info('init()')

	def load(self):
		self._logger.info('load')

		_data = read_json_file(self._path, {})
		for message_uuid, row in _data.items():
			message = Message()
			message.uuid = message_uuid
			message.from_dict(row)

			self._logger.debug('load message: %s', message)

			self._messages_by_uuid[message_uuid] = message

	def save(self) -> bool:
		self._logger.info('save() changes=%s', self._changes)

		if not self._changes:
			return False

		_data = dict()
		for message_uuid, message in self._messages_by_uuid.items():
			_data[message_uuid] = message.as_dict()

		write_json_file(self._path, _data)
		self._changes = False

		return True

	def add_message(self, message: Message):
		self._logger.debug('add_message(%s)', message)

		self._messages_by_uuid[message.uuid] = message
		self._changes = True

	def get_messages(self) -> dict:
		return self._messages_by_uuid.items()

	def has_message(self, message_uuid: str) -> bool:
		self._logger.debug('has_message(%s)', message_uuid)
		return message_uuid in self._messages_by_uuid

	def changed(self):
		self._changes = True

	def clean_up(self):
		self._logger.info('clean up')

		remove_messages = []

		ffunc = lambda _message: dt.datetime.utcnow() - _message[1].created_at >= self._message_retention_time
		old_messages = list(filter(ffunc, self._messages_by_uuid.items()))
		self._logger.debug('old_messages A: %s', old_messages)
		remove_messages += old_messages

		ffunc = lambda _message: _message[1].is_delivered
		old_messages = list(filter(ffunc, self._messages_by_uuid.items()))
		self._logger.debug('old_messages B: %s', old_messages)
		remove_messages += old_messages

		for message_uuid, message in remove_messages:
			self._logger.debug('remove message: %s', message)
			del self._messages_by_uuid[message_uuid]
			self._changes = True

class Database():
	_path: str
	_messages: dict
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
		for message_uuid, message_raw in data.items():
			message = Message()
			message.from_dict(message_raw)

			self._data[message_uuid] = message

	def save(self):
		self._logger.info('save() changes=%s', self._changes)

		if not self._changes:
			return

		data = dict()
		for message_uuid, message in self._data.items():
			data[message_uuid] = message.as_dict()

		write_json_file(self._path, data)
		self._changes = False

	def add_message(self, message: Message):
		self._logger.debug('add_message %s', message)

		self._data[message.uuid] = message
		self._changes = True

	def has_message(self, message_uuid: str) -> bool:
		self._logger.debug('has_message %s', message_uuid)
		return message_uuid in self._data
