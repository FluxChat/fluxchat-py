
import datetime as dt
from traceback import format_exc
from json import dumps, loads
from logging import getLogger, basicConfig, Logger
from typing import Optional, cast
from sty import fg
from os import path
from asyncio import create_task, gather, sleep as asleep
from aiohttp.web import TCPSite, Application as WebApplication, AppRunner as WebAppRunner, Response as WebResponse, get as wget, post as wpost, delete as wdelete
from aiohttp.web_request import Request as WebRequest
from base64 import b64encode, b64decode

from lib.database import Database
from lib.helper import read_json_file
from lib.mail import Mail
from lib.overlay import Node, NodeError
from lib.server import Server
from lib.scheduler import Scheduler


class RestApiError(Exception):
	status: int = 500


class RestApiServerError(RestApiError):
	pass


class ServerApp():
	_running: bool
	_config_file: str
	_config: dict
	_server: Server
	_scheduler: Scheduler
	_is_dev: bool
	_logger: Logger
	_loglevel: Optional[str]
	_api_app: Optional[WebApplication]
	_api_runner: Optional[WebAppRunner]
	_api_site: Optional[TCPSite]

	def __init__(self, config_file: str, is_dev: bool = False, loglevel: Optional[str] = None):
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

				self._logger.debug('create API thread')
				tasks.append(create_task(self.run_restapi(restapi_config['address'], restapi_config['port'])))

		# Wait for threads.
		self._logger.debug('wait for threads')
		await gather(*tasks)

		# End
		self._logger.info('run finished')

	async def shutdown(self, reason: Optional[str] = None):
		self._running = False
		self._logger.info('shutdown(%s)', reason)
		self._scheduler.shutdown(reason)
		if self._api_app:
			await self._api_app.shutdown()
		if self._api_runner:
			await self._api_runner.shutdown()

	async def get_database_for_restapi(self) -> Database:
		server_db = self._server.get_database()
		if server_db is None:
			exception = RestApiServerError('Database is not available')
			raise exception
		return server_db

	async def run_restapi(self, address: str, port: int):
		self._api_app = WebApplication()
		self._api_app.add_routes([
			wget('/', self._handle_restapi),
			wget('/v1', self._handle_restapi),
			wget('/v1/infos', self._get_infos),
			wget('/v1/clients', self._get_clients),
			wget('/v1/mails', self._get_mails),
			wpost('/v1/mails', self._post_mails),
			wget('/v1/queue', self._get_queue),
			wpost('/v1/queue', self._post_handle_mail_queue),
			wdelete('/v1/queue', self._delete_mail_queue),
			wget('/v1/nodes', self._get_nodes),
			wpost('/v1/save', self._post_save),
			wpost('/v1/db', self._post_handle_mail_db),
		])

		self._api_runner = WebAppRunner(self._api_app)
		await self._api_runner.setup()

		self._api_site = TCPSite(self._api_runner, address, port)
		await self._api_site.start()

		tick = 0
		while self._running:
			await asleep(1)
			tick += 1

	async def _handle_restapi(self, request: WebRequest):
		print(f'-> request: {request} {type(request)}')

		json = {'status': f'OK'}
		response = WebResponse(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_infos(self, request: WebRequest):
		print(f'-> _get_infos')

		db_server = self._server.get_database()
		if db_server is None:
			db_infos = {
				'clients': 'N/A',
				'mails': 'N/A',
				'queue': 'N/A',
			}
		else:
			db_infos = {
				'clients': db_server.get_clients_len(),
				'mails': len(db_server.get_mails()),
				'queue': len(db_server.get_queue_mails()),
			}

		json = {
			'node': {
				'id': self._server.get_local_node().pubid,
				'contact': self._server.get_contact(),
			},
			'server': {
				'is_bootstrap_phase': self._server.is_bootstrap_phase(),
				**db_infos,
			}
		}
		response = WebResponse(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_clients(self, request: WebRequest):
		print(f'-> _get_clients')

		clients = []
		for client in self._server.get_clients():
			client_d = client.as_dict()
			client_d['has_public_key'] = client.has_public_key()
			client_d['has_contact_info'] = client.has_contact()
			client_d['conn_mode'] = client.conn_mode
			client_d['conn_msg'] = client.conn_msg
			client_d['dir_mode'] = client.dir_mode
			client_d['auth'] = client.auth
			client_d['cash'] = client.cash
			clients.append(client_d)
		response = WebResponse(
			text=dumps(clients, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_mails(self, request: WebRequest):
		print(f'-> _get_mails')

		mails = []
		if server_db := self._server.get_database():
			for uuid, message in server_db.get_mails().items():
				mails.append(message.as_dict())

		response = WebResponse(
			text=dumps(mails, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _post_mails(self, request: WebRequest):
		print(f'-> _post_mails')

		try:
			local_node = self._server.get_local_node()
			server_db = await self.get_database_for_restapi()

			content = await request.json()

			body_is_base64 = False
			if 'is_base64' in content:
				body_is_base64 = bool(content['is_base64'])

			mail = Mail()
			mail.set_sender(local_node.pubid)
			if 'target' in content:
				mail.set_receiver(content['target'], True)
			if 'subject' in content:
				mail.subject = content['subject']
			if 'body' in content:
				body = cast(str, content['body'])
				if body_is_base64:
					mail.body = b64decode(body).decode()
				else:
					mail.body = body
				mail.mcompile()

			queued_mails = server_db.add_queue_mail(mail)

			json = {
				'status': 'OK',
				'request': content,
				'mail': {
					'uuid': mail.uuid,
					'pubid': mail.pubid,
					'valid_until': mail.valid_until,
				},
				'queued_mails': queued_mails,
			}
			response = WebResponse(
				text=dumps(json, indent=4, default=str),
				content_type='application/json',
			)
			return response
		except NodeError as error:
			json = {
				'status': 'ERROR',
				'message': str(error),
				'exception_traceback': format_exc(),
			}
			response = WebResponse(
				status=400,
				text=dumps(json, indent=4, default=str),
				content_type='application/json',
			)
			return response
		except RestApiError as error:
			json = {
				'status': 'ERROR',
				'message': str(error),
				'exception_traceback': format_exc(),
			}
			response = WebResponse(
				status=error.status,
				text=dumps(json, indent=4, default=str),
				content_type='application/json',
			)
			return response
		except Exception as error:
			json = {
				'status': 'UNKNOWN_EXCEPTION',
				'message': str(error),
				'exception_traceback': format_exc(),
			}
			response = WebResponse(
				status=500,
				text=dumps(json, indent=4, default=str),
				content_type='application/json',
			)
			return response

	async def _get_queue(self, request: WebRequest):
		print(f'-> _get_queue')

		messages = []
		if server_db := self._server.get_database():
			for uuid, message in server_db.get_queue_mails().items():
				messages.append(message.as_dict())

		response = WebResponse(
			text=dumps(messages, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _get_nodes(self, request: WebRequest):
		print(f'-> _get_nodes')

		nodes = []
		if server_db := self._server.get_database():
			for cuuid, client in server_db.get_clients().items():
				nodes.append(client.as_dict())

		response = WebResponse(
			text=dumps(nodes, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _post_save(self, request: WebRequest):
		print(f'-> _post_save')

		if server_db := self._server.get_database():
			server_db.save()

		json = {'status': 'OK'}
		response = WebResponse(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _post_handle_mail_db(self, request: WebRequest):
		print(f'-> _post_handle_mail_db')

		self._server.handle_mail_db()

		json = {'status': 'OK'}
		response = WebResponse(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _post_handle_mail_queue(self, request: WebRequest):
		print(f'-> _post_handle_mail_queue')

		self._server.handle_mail_queue()

		json = {'status': 'OK'}
		response = WebResponse(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response

	async def _delete_mail_queue(self, request: WebRequest):
		print(f'-> _delete_mail_queue')

		json = {
			'status': 'OK',
			'old_mail_queue': self._server.delete_mail_queue(),
		}
		response = WebResponse(
			text=dumps(json, indent=4, default=str),
			content_type='application/json',
		)
		return response
