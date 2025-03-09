
import datetime as dt
from json import dumps
from logging import getLogger, basicConfig, Logger
from typing import Optional
from sty import fg
from os import path
from asyncio import create_task, gather, sleep as asleep
from aiohttp import web, web_request

from lib.helper import read_json_file
# from lib.restapi import get_restapi_app
from lib.server import Server
from lib.scheduler import Scheduler


class ServerApp():
	_running: bool
	_config_file: str
	_config: dict
	_server: Server
	_scheduler: Scheduler
	_is_dev: bool
	_logger: Logger
	_loglevel: str
	_api_app: Optional[web.Application]
	_api_runner: Optional[web.AppRunner]
	_api_site: Optional[web.TCPSite]

	def __init__(self, config_file: str = None, is_dev: bool = False, loglevel: str = None):
		self._running = False
		self._config_file = config_file
		self._config = None
		self._server = None
		self._scheduler = None
		self._is_dev = is_dev
		self._logger = None
		self._loglevel = loglevel
		self._api_app = None
		self._api_runner = None
		self._api_site = None

	def start(self): # pragma: no cover
		# Init
		self._load_config()

		# Logging
		if 'log' not in self._config:
			self._config['log'] = {}

		if 'file' in self._config['log'] and self._config['log']['file']:
			if '/' not in self._config['log']['file'] and self._config['log']['file'][0] != '/':
				self._config['log']['file'] = path.join(self._config['data_dir'], self._config['log']['file'])

		if 'level' not in self._config['log']:
			self._config['log']['level'] = 'warning'

		if self._loglevel is not None:
			self._config['log']['level'] = self._loglevel
		self._config['log']['level'] = self._config['log']['level'].upper()

		logConfig = {
			'level': self._config['log']['level'],
			'format': '%(asctime)s %(process)d %(levelname)-7s %(name)-17s %(message)s',
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

	async def run(self):
		self._running = True
		self._logger.info('run()')
		tasks = []
		tasks.append(create_task(self._scheduler.run()))

		if 'restapi' in self._config:
			restapi_config = self._config['restapi']
			if 'enabled' in restapi_config and restapi_config['enabled'] \
				and 'address' in restapi_config \
				and 'port' in restapi_config:
				tasks.append(create_task(self.run_restapi(restapi_config['address'], restapi_config['port'])))
		await gather(*tasks)
		self._logger.info('run finished')

	async def shutdown(self, reason: str = None):
		self._running = False
		self._logger.info('shutdown(%s)', reason)
		self._scheduler.shutdown(reason)
		if self._api_app:
			await self._api_app.shutdown()
			await self._api_runner.shutdown()

	async def run_restapi(self, address: str, port: int):
		self._api_app = web.Application()
		self._api_app.add_routes([
			web.get('/', self._handle_restapi),
			web.get('/v1/infos', self._get_infos),
			web.get('/v1/clients', self._get_clients),
			web.get('/v1/messages', self._get_messages),
			web.get('/v1/queue', self._get_queue),
			web.get('/v1/addresses', self._get_addresses),
		])

		self._api_runner = web.AppRunner(self._api_app)
		await self._api_runner.setup()

		self._api_site = web.TCPSite(self._api_runner, 'localhost', 26002)
		await self._api_site.start()

		tick = 0
		while self._running:
			await asleep(1)
			tick += 1

	async def _handle_restapi(self, request: web_request.Request):
		print(f'-> request: {request} {type(request)}')

		# name = request.match_info.get('api_version', 'v1')
		json = {'status': f'OK'}
		response = web.Response(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_infos(self, request: web_request.Request):
		print(f'-> _get_infos')

		json = {
			'server': {
				'is_bootstrap_phase': self._server.is_bootstrap_phase(),
			}
		}
		response = web.Response(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_clients(self, request: web_request.Request):
		print(f'-> _get_clients')

		clients = []
		for client in self._server.get_clients():
			clients.append(client.as_dict())
		json = {'clients': clients}
		response = web.Response(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_messages(self, request: web_request.Request):
		print(f'-> _get_messages')

		messages = []
		if mail_db := self._server.get_mail_db():
			for uuid, message in mail_db.get_mails().items():
				messages.append(message.as_dict())

		json = {'messages': messages}
		response = web.Response(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_queue(self, request: web_request.Request):
		print(f'-> _get_queue')

		messages = []
		if mail_queue := self._server.get_mail_queue():
			for uuid, message in mail_queue.get_mails().items():
				messages.append(message.as_dict())

		json = {'messages': messages}
		response = web.Response(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_addresses(self, request: web_request.Request):
		print(f'-> _get_addresses')

		addresses = []
		if address_book := self._server.get_addressbook():
			for cuuid, client in address_book.get_clients().items():
				addresses.append(client.as_dict())

		json = {'addresses': addresses}
		response = web.Response(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response
