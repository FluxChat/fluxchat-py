
import os
import json

from sty import fg
from lib.json_file import JsonFile
from lib.server import Server

class PyChat(JsonFile):
	_config_file: str
	_config: dict
	_running: bool

	def __init__(self, config_file: str = None):
		print('-> PyChat.__init__()')

		self._config_file = config_file

		# Init
		self._load_config()

	def __del__(self):
		print('-> PyChat.__del__()')

	def _load_config(self):
		print('-> PyChat._load_config()')

		self._config = self._read_json_file(self._config_file)

	def run(self):
		print('-> PyChat.run()')
		self._running = True

		server = Server(self._config['node'])

	def shutdown(self):
		self._running = False
