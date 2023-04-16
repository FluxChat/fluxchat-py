
import logging
import socket
import base64
import time
import json

from lib.network import Network
from lib.helper import read_json_file
from lib.mail import Message

class Ipc(Network):
	_config_file: str
	_config: dict
	_ipc_config: dict

	def __init__(self, config_file: str = None):
		self._config_file = config_file

		self._logger = logging.getLogger('server')
		self._logger.info('init')

	def start(self): # pragma: no cover
		self._load_config()

		if not self._ipc_config['enabled']:
			raise Exception('IPC is not enabled')

	def _load_config(self):
		self._config = read_json_file(self._config_file)
		self._ipc_config = self._config['ipc']

	def send(self, target: str, subject: str, message: str) -> bool:
		self._logger.info('send(%s, %s)', target, subject)

		raw = "\n".join(['From: ' + self._config['id'], 'Subject: ' + subject, message])
		raw = base64.b64encode(raw.encode('utf-8')).decode('utf-8')

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		try:
			self._logger.debug('sock.connect to %s:%s', self._ipc_config['address'], self._ipc_config['port'])
			sock.connect((self._ipc_config['address'], self._ipc_config['port']))
			self._logger.debug('-> sock.connect done')
		except ConnectionRefusedError as e:
			self._logger.error('-> ConnectionRefusedError: %s', e)
			return False
		except TimeoutError as e:
			self._logger.error('-> TimeoutError: %s', e)
			return False
		except socket.timeout as e:
			self._logger.error('-> socket.timeout: %s', e)
			return False

		sock.settimeout(None)
		self._client_send_message(sock, target, raw)
		time.sleep(0.1) # TODO replace with selectors
		sock.close()

		return True

	def _client_send_ok(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_message(self, sock: socket.socket, target: str, raw: str): # pragma: no cover
		self._logger.debug('_client_send_message()')
		self._client_write(sock, 1, 0, [target, raw])
