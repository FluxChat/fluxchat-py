
import datetime as dt

class Task():
	# _execfunc
	_interval: dt.timedelta
	_last_run: dt.datetime
	is_one_shot: bool

	def __init__(self, execfunc, interval: dt.timedelta = None, one_shot: bool = False):
		print('-> Task.__init__({}, {})'.format(execfunc, interval))
		self._execfunc = execfunc
		self._interval = interval
		self._last_run = None
		self.is_one_shot = one_shot

		if self._interval != None and one_shot:
			self._last_run = dt.datetime.now()

	def run(self) -> bool:
		should_run = False
		if self._last_run is None:
			should_run = True
		else:
			diff = dt.datetime.now() - self._last_run
			if diff > self._interval:
				should_run = True

		if should_run:
			# print('-> Task.run()')
			exec_res = self._execfunc()
			self._last_run = dt.datetime.now()
			# print('-> exec_res', exec_res)
			return exec_res

		return False
