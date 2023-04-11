
import os
import json
import time
import datetime as dt

from sty import fg
from lib.helper import read_json_file
from lib.server import Server
from lib.scheduler import Scheduler

class PyChat():
	_config_file: str
	_config: dict
	_server: Server
	_scheduler: Scheduler

	def __init__(self, config_file: str = None):
		# print('-> PyChat.__init__()')
		self._config_file = config_file

	def start(self): # pragma: no cover
		# Init
		self._load_config()
		self._server = Server(self._config)
		self._server.start()

		self._scheduler = Scheduler()
		self._scheduler.add_task(self._server.run, dt.timedelta(milliseconds=100))

		# TODO change that to every 5 minutes, one_shot=False
		self._scheduler.add_task(self._server.contact_address_book, dt.timedelta(seconds=5), one_shot=True)

		self._scheduler.add_task(self._server.handle_clients, dt.timedelta(milliseconds=100))

		# TODO change that to every 5 minutes
		self._scheduler.add_task(self._server.clean_up, dt.timedelta(seconds=15))

		# TODO activate for production
		#self._scheduler.add_task(self._server.ping_clients, dt.timedelta(seconds=15))

		# TODO change that to every 5 minutes
		self._scheduler.add_task(self._server.save, dt.timedelta(seconds=15))

		# TODO deactivate for production
		self._scheduler.add_task(self._server.debug_clients, dt.timedelta(minutes=1))

		self._scheduler.add_task(self._server.client_actions, dt.timedelta(seconds=15))
		self._scheduler.add_task(self._server.handle_message_queue, dt.timedelta(seconds=15))

	def _load_config(self):
		# print('-> PyChat._load_config()')
		self._config = read_json_file(self._config_file)

	def run(self):
		# print('-> PyChat.run()')
		self._scheduler.run()

	def shutdown(self):
		# print('-> PyChat.shutdown()')
		self._scheduler.shutdown()
