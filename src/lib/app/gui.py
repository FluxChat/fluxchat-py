
import tkinter as tk
from logging import Logger, basicConfig, getLogger
from lib.gui import MainFrame
from lib.helper import read_json_file


class GuiApp():
	_config_file: str
	_config: dict
	_logger: Logger
	_tk_root: tk.Tk

	def __init__(self, config_file: str = None, is_dev: bool = False, loglevel: str = None):
		self._config_file = config_file
		self._config = None
		self._is_dev = is_dev
		self._logger = None
		self._loglevel = loglevel

	def start(self): # pragma: no cover
		# Init
		self._load_config()

		# Logging
		if 'log' not in self._config:
			self._config['log'] = {}

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

		self._logger = getLogger('app.gui')
		self._logger.info('start')

	def _load_config(self):
		self._config = read_json_file(self._config_file)

	async def run(self):
		root = tk.Tk()
		root.title('FluxChat')
		# root.geometry("400x200")

		main_frame = MainFrame(root)
		main_frame.mainloop()
