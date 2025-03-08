
import datetime as dt
from logging import getLogger, basicConfig, Logger
from sty import fg
from os import path

from lib.helper import read_json_file
from lib.server import Server
from lib.scheduler import Scheduler


class ServerApp():
	_config_file: str
	_config: dict
	_server: Server
	_scheduler: Scheduler
	_is_dev: bool
	_logger: Logger
	_loglevel: str

	def __init__(self, config_file: str = None, is_dev: bool = False, loglevel: str = None):
		self._config_file = config_file
		self._config = None
		self._server = None
		self._scheduler = None
		self._is_dev = is_dev
		self._logger = None
		self._loglevel = loglevel

	def start(self): # pragma: no cover
		# Init
		self._load_config()

		# Logging
		if not 'log' in self._config:
			self._config['log'] = {}

		if 'file' in self._config['log'] and self._config['log']['file']:
			if '/' not in self._config['log']['file'] and self._config['log']['file'][0] != '/':
				self._config['log']['file'] = path.join(self._config['data_dir'], self._config['log']['file'])

		if not 'level' in self._config['log']:
			self._config['log']['level'] = 'warning'

		if self._loglevel != None:
			self._config['log']['level'] = self._loglevel
		self._config['log']['level'] = self._config['log']['level'].upper()

		logConfig = {
			'level': self._config['log']['level'],
			'format': '%(asctime)s %(process)d %(levelname)-8s %(name)-13s %(message)s',
		}
		if not self._is_dev:
			if 'file' in self._config['log'] and self._config['log']['file']:
				logConfig['filename'] = self._config['log']['file']
			logConfig['filemode'] = 'a'
		basicConfig(**logConfig)

		self._logger = getLogger('app.server')
		self._logger.info('start')

		# Server
		self._server = Server(self._config)
		self._server.start()

		self._scheduler = Scheduler()
		self._scheduler.add_task(self._server.handle_sockets, dt.timedelta(milliseconds=100))
		self._scheduler.add_task(self._server.handle_clients, dt.timedelta(milliseconds=100))
		self._scheduler.add_task(self._server.client_actions, dt.timedelta(seconds=15))
		self._scheduler.add_task(self._server.handle_mail_queue, dt.timedelta(seconds=10))
		self._scheduler.add_task(self._server.handle_mail_db, dt.timedelta(seconds=10))

		if self._is_dev:
			self._scheduler.add_task(self._server.contact_address_book, dt.timedelta(seconds=5), one_shot=True)
			self._scheduler.add_task(self._server.clean_up, dt.timedelta(seconds=15))
			self._scheduler.add_task(self._server.save, dt.timedelta(seconds=15))
			self._scheduler.add_task(self._server.debug_clients, dt.timedelta(minutes=1))
		else:
			self._scheduler.add_task(self._server.contact_address_book, dt.timedelta(minutes=5))
			self._scheduler.add_task(self._server.clean_up, dt.timedelta(minutes=5))
			self._scheduler.add_task(self._server.ping_clients, dt.timedelta(seconds=60))
			self._scheduler.add_task(self._server.save, dt.timedelta(minutes=5))

	def _load_config(self):
		self._config = read_json_file(self._config_file)

	def run(self):
		self._logger.info('run()')
		self._scheduler.run()
		self._logger.info('run finished')

	def shutdown(self, reason: str = None):
		self._logger.info('shutdown(%s)', reason)
		self._scheduler.shutdown(reason)
