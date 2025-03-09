
from typing import Callable
import datetime as dt


class Task():
	_execfunc: Callable
	_interval: dt.timedelta
	_last_run: dt.datetime
	is_one_shot: bool

	def __init__(self, execfunc, interval: dt.timedelta = None, one_shot: bool = False):
		self._execfunc = execfunc
		self._interval = interval
		self._last_run = None
		self.is_one_shot = one_shot

		if self._interval is not None and one_shot:
			self._last_run = dt.datetime.now(dt.UTC)

	def __str__(self): # pragma: no cover
		return 'Task({})'.format(self._execfunc)

	def __repr__(self): # pragma: no cover
		return self.__str__()

	def run(self) -> bool:
		should_run = False
		if self._last_run is None:
			should_run = True
		else:
			diff = dt.datetime.now(dt.UTC) - self._last_run
			if diff > self._interval:
				should_run = True

		if should_run:
			exec_res = self._execfunc()
			self._last_run = dt.datetime.now(dt.UTC)
			return exec_res

		return False
