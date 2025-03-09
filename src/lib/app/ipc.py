
import datetime as dt
from logging import getLogger, basicConfig, DEBUG
from selectors import DefaultSelector, EVENT_READ
from socket import socket as Socket, timeout as SocketTimeout, AF_INET, AF_INET6, SOCK_STREAM
from typing import Optional

from lib.network import Network, SocketReadStatus
from lib.helper import read_json_file
from lib.mail import Mail
from lib.scheduler import Scheduler


class IpcCommand():
	type: str
	waiting: bool
	def __init__(self, type: str = None, data = None):
		self.type = type
		self.data = data
		self.waiting = False


class IpcApp(Network):
	_config_file: str
	_config: dict
	_ipc_config: dict
	_selectors: DefaultSelector
	_commands: list
	_scheduler: Scheduler
	_client_socket: Socket

	def __init__(self, config_file: str = None, loglevel: str = None):
		self._config_file = config_file
		self._loglevel = loglevel
		self._selectors = DefaultSelector()
		self._commands = []
		self._scheduler = None
		self._client_socket = None

		logConfig = {
			'level': self._loglevel,
			'format': '%(asctime)s %(process)d %(levelname)-8s %(name)-13s %(message)s',
		}
		basicConfig(**logConfig)

		self._logger = getLogger('app.ipc')
		self._logger.info('init()')

	def __del__(self):
		self._logger.info('__del__()')
		self._selectors.close()

	def add_command(self, command: IpcCommand):
		self._logger.info('add_command(%s)', command.type)
		self._commands.append(command)

	def append_to_command(self, type: str, data):
		self._logger.info('append_to_command()')

	def get_command_by_type(self, type: str) -> IpcCommand:
		self._logger.info('get_command_by_type(%s)', type)
		for command in self._commands:
			if command.type == type:
				return command
		return None

	def start(self):
		self._load_config()

		if not self._ipc_config['enabled']:
			raise Exception('IPC is not enabled')

		logConfig = {
			'level': DEBUG,
			'format': '%(asctime)s %(process)d %(levelname)-8s %(name)-13s %(message)s',
		}
		basicConfig(**logConfig)

		self.add_command(IpcCommand('_client_connect'))

		self._scheduler = Scheduler()
		self._scheduler.add_task(self.handle_sockets, dt.timedelta(milliseconds=100))
		self._scheduler.add_task(self.handle_commands, dt.timedelta(milliseconds=100))

	async def run(self):
		self._logger.info('run()')
		await self._scheduler.run()
		self._logger.info('run finished')

	def shutdown(self, reason: str = None):
		self._logger.info('shutdown(%s)', reason)
		self._scheduler.shutdown(reason)

	def stop(self):
		self._logger.info('stop()')

		self.add_command(IpcCommand('_stop'))

	def _load_config(self):
		self._config = read_json_file(self._config_file)
		self._ipc_config = self._config['ipc']

	def handle_commands(self):
		self._logger.info('handle_commands() -> %d', len(self._commands))

		commands = self._commands
		self._commands = []

		for command in commands:
			self._logger.info('command: %s', command.type)

			if command.type == '_client_connect':
				self._client_socket = self._client_connect()
				if not self._client_socket:
					self._logger.error('failed to connect to client')
					self.stop()

			elif command.type == '_client_disconnect':
				self._client_disconnect(self._client_socket)

			elif command.type == '_stop':
				self._scheduler.shutdown('stop')

			elif command.type == '_list_mails':
				self._logger.info('command data: %s', command.data)

				print('-> list_mails')
				print('ID                                    RECEIVED_AT          FROM                                             SUBJECT')
				row_f = '{uuid}  {received_at}  {sender}  {subject}'

				for mail in command.data:
					self._logger.info('mail: %s', mail)

					mail_d = mail.as_dict()
					mail_d['uuid'] = mail.uuid
					# print(mail_d)

					row = row_f.format(**mail_d)
					print(row)

				print('<- list_mails')
				self.stop()

			elif command.type == '_read_mail_found':
				self._logger.info('command data: %s', command.data)

				mail: Mail = command.data
				# print(mail)

				print('-> read_mail')
				print()

				print('ID: %s' % mail.uuid)
				print('CREATED AT:  %s' % mail.created_at)
				print('RECEIVED AT: %s' % mail.received_at)
				# print('VALID UNTIL: %s' % mail.valid_until)
				print('IS ENCRYPTED: %s' % mail.is_encrypted)
				print('VERIFY STATUS: %s' % mail.verified)
				print('FROM: %s' % mail.sender)
				print('TO:   %s' % mail.receiver)
				print('SUBJECT: %s' % mail.subject)
				print()
				print('----- BEGIN BODY -----\n%s\n----- END BODY -----' % mail.body)
				print()

				print('<- read_mail')

				self.stop()

			elif command.type == '_read_mail_not_found':
				print('-> mail not found')
				print('<- read_mail')
				self.stop()

			if self._client_socket:
				if command.type == 'send_mail':
					self._logger.info('command data: %s', command.data)
					self._client_send_send_mail(self._client_socket, command.data['target'], command.data['raw'])

				elif command.type == 'list_mails':
					self._client_send_list_mails(self._client_socket, command.data['only_new'])

				elif command.type == 'read_mail':
					self._client_send_read_mail(self._client_socket, command.data['uuid'])

				elif command.type == 'save':
					self._client_send_save(self._client_socket)

			if command.waiting:
				self._commands.append(command)

	def send_mail_command(self, target: str, subject: str, body: str) -> bool:
		self._logger.info('send_mail_command(%s, %s)', target, subject)

		mail = Mail()
		mail.sender = self._config['id']
		mail.receiver = target
		mail.subject = subject
		mail.body = body

		raw = mail.encode()

		command = IpcCommand('send_mail')
		command.data = {
			'target': target,
			'raw': raw,
		}
		self.add_command(command)

	def list_mails_command(self, only_new: bool = False) -> bool:
		self._logger.info('list_mails_command(%s)', only_new)

		command = IpcCommand('list_mails')
		command.data = {
			'only_new': only_new,
		}
		self.add_command(command)

	def read_mail_command(self, m_uuid: str) -> bool:
		self._logger.info('read_mail_command(%s)', m_uuid)

		command = IpcCommand('read_mail')
		command.data = {
			'uuid': m_uuid,
		}
		self.add_command(command)

	def save_command(self):
		self._logger.info('save_command()')

		self.add_command(IpcCommand('save'))

	def handle_sockets(self):
		self._logger.debug('handle_sockets()')

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			self._logger.debug('socket event: %s %d', key, mask)

			if key.data['type'] == 'client':
				status = self._client_read(key.fileobj)

				if status.disconnect:
					self._logger.debug('client disconnect')
					self.stop()

				self._client_commands(key.fileobj, status.commands)

	def _client_commands(self, sock: Socket, commands: list):
		self._logger.debug('_handle_client(%s)', sock)
		self._logger.debug('commands: %s', commands)

		for command_raw in commands:
			group_i, command_i, payload = command_raw
			payload_len = len(payload)

			self._logger.debug('group: %d, command %d', group_i, command_i)
			self._logger.debug('payload: %s', payload)

			if group_i == 1:
				if command_i == 1:
					print('-> receive mails from server')

					chunks_len, chunk_num = payload[0:2]
					chunks_len_i = int.from_bytes(chunks_len.encode(), 'little')
					chunk_num_i = int.from_bytes(chunk_num.encode(), 'little')

					self._logger.debug('chunks_len_i: %s', chunks_len_i)
					self._logger.debug('chunk_num_i: %s', chunk_num_i)

					mails_encoded = payload[2:]
					self._logger.debug('mails_encoded: %s', mails_encoded)

					_command = self.get_command_by_type('_list_mails')
					if _command is None:
						self._logger.debug('command not found')
						_command = IpcCommand('_list_mails', [])
						_command.waiting = True
						self.add_command(_command)

					if chunk_num_i + 1 >= chunks_len_i:
						self._logger.debug('chunk_num_i >= chunks_len_i')
						_command.waiting = False

					for mail_encoded in mails_encoded:
						self._logger.debug('mail_encoded: "%s"', mail_encoded)

						mail = Mail('N/A')
						mail.ipc_decode(mail_encoded.encode())

						self._logger.debug('mail: %s', mail)

						_command.data.append(mail)

				if command_i == 2:
					print('-> receive mail from server')

					mail_found = int.from_bytes(payload[0], 'little')
					if mail_found == 1:
						mail_encoded = payload[1].decode()
						self._logger.debug('mail_encoded: %s', mail_encoded)

						mail = Mail('N/A')
						mail.ipc_decode(mail_encoded.encode())

						self.add_command(IpcCommand('_read_mail_found', mail))
					else:
						self.add_command(IpcCommand('_read_mail_not_found'))

	def _client_connect(self):
		self._logger.info('_client_connect()')

		# IPv4
		sock = Socket(AF_INET, SOCK_STREAM)
		sock.settimeout(2)
		try:
			self._logger.debug('sock.connect to %s:%s', self._ipc_config['address'], self._ipc_config['port'])
			sock.connect((self._ipc_config['address'], self._ipc_config['port']))
			self._logger.debug('sock.connect done')
		except ConnectionRefusedError as e:
			self._logger.error('ConnectionRefusedError: %s', e)
			return False
		except TimeoutError as e:
			self._logger.error('TimeoutError: %s', e)
			return False
		except SocketTimeout as e:
			self._logger.error('SocketTimeout: %s', e)
			return False
		sock.settimeout(None)
		sock.setblocking(False)

		self._selectors.register(sock, EVENT_READ, data={'type': 'client'})

		return sock

	def _client_send_ok(self, sock: Socket):
		self._logger.debug('_client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_send_mail(self, sock: Socket, target: str, raw: str):
		self._logger.debug('_client_send_send_mail()')
		self._logger.debug('sock: %s', sock)
		self._logger.debug('target: %s', target)
		self._logger.debug('raw: %s', raw)

		self._client_write(sock, 1, 0, [target, raw])

	def _client_send_list_mails(self, sock: Socket, only_new: bool = False):
		self._logger.debug('_client_send_list_mails()')
		self._logger.debug('sock: %s', sock)
		self._logger.debug('only_new: %s', only_new)

		flags = 0
		if only_new:
			flags |= 1

		data = [
			flags,
		]

		self._client_write(sock, 1, 1, data)

	def _client_send_read_mail(self, sock: Socket, m_uuid: str):
		self._logger.debug('_client_send_read_mail()')
		self._logger.debug('sock: %s', sock)

		data = [
			m_uuid,
		]

		self._client_write(sock, 1, 2, data)

	def _client_send_save(self, sock: Socket):
		self._logger.debug('_client_send_save()')
		self._client_write(sock, 2, 0)

	def _client_disconnect(self, sock: Socket):
		self._logger.info('_client_disconnect()')
		self._client_send_ok(sock)
		sock.close()
