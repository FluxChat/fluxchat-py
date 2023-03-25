
import datetime as dt

class Task():
	# _execfunc
	_interval: dt.timedelta
	_last_run: dt.datetime

	def __init__(self, execfunc, interval: dt.timedelta):
		print('-> Task.__init__({}, {})'.format(execfunc, interval))
		self._execfunc = execfunc
		self._interval = interval
		self._last_run = None

	def run(self) -> bool:
		should_run = False
		if self._last_run is None:
			should_run = True
		else:
			diff = dt.datetime.now() - self._last_run
			if diff > self._interval:
				should_run = True

		if should_run:
			print('-> Task.run()')
			exec_res = self._execfunc()
			self._last_run = dt.datetime.now()
			print('-> exec_res', exec_res)
			return exec_res

		return False
