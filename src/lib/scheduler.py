
import datetime as dt
from time import sleep
from logging import getLogger
from lib.task import Task


class Scheduler():
	_running: bool
	_tasks: list
	MAX_TIME = 0.2
	SLEEP_TIME = 0.3
	IDLE_MULTIPLIER = 1.5
	MAX_SLEEP_TIME = 10

	def __init__(self):
		self._running = False
		self._tasks = []

		self._logger = getLogger('app.scheduler')
		self._logger.info('init()')

	def __del__(self):
		self._logger.info('__del__()')

	def add_task(self, execfunc, interval: dt.timedelta = None, one_shot: bool = False):
		self._logger.debug('add_task(%s, %s)', execfunc, interval)
		task = Task(execfunc, interval, one_shot)
		self._tasks.append(task)

	def run(self, max_cycles: int = None):
		self._logger.info('run()')
		self._running = True
		_sleep_time = self.SLEEP_TIME

		_cycle = 0
		while (self._running and max_cycles == None) or (max_cycles != None and _cycle < max_cycles):
			_start = dt.datetime.utcnow()

			tasks_running = 0
			for task in self._tasks:
				# self._logger.debug('run task %s', task)
				was_running = task.run()
				if was_running:
					tasks_running += 1
					if task.is_one_shot:
						# self._logger.debug('removing one shot task')
						self._tasks.remove(task)

				_diff = dt.datetime.utcnow() - _start
				if _diff > dt.timedelta(seconds=self.MAX_TIME):
					# self._logger.debug('run() exceeded max time')
					break

			if tasks_running == 0:
				_sleep_time = _sleep_time * self.IDLE_MULTIPLIER
				if _sleep_time > self.MAX_SLEEP_TIME:
					_sleep_time = self.MAX_SLEEP_TIME
				# self._logger.debug('_sleep_time', _sleep_time)
			else:
				_sleep_time = self.SLEEP_TIME

			#self._logger.debug('sleeping: {}'.format(_sleep_time))
			sleep(_sleep_time)

			_cycle += 1

		self._logger.info('run() finished after %s cycles', _cycle)

	def shutdown(self, reason: str = None):
		self._logger.info('shutdown: %s', reason)
		self._running = False
