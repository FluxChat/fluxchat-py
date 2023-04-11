
import time
import datetime as dt
from lib.task import Task

class Scheduler():
	_running: bool
	_tasks: list
	MAX_TIME = 0.2
	SLEEP_TIME = 0.3
	IDLE_MULTIPLIER = 1.5
	MAX_SLEEP_TIME = 10

	def __init__(self):
		# print('-> Scheduler.__init__()')
		self._running = False
		self._tasks = []

	def add_task(self, execfunc, interval: dt.timedelta = None, one_shot: bool = False):
		# print('-> Scheduler.add_task({}, {})'.format(execfunc, interval))
		task = Task(execfunc, interval, one_shot)
		self._tasks.append(task)

	def run(self, max_cycles: int = None):
		# print('-> Scheduler.run()')
		self._running = True
		_sleep_time = self.SLEEP_TIME

		_cycle = 0
		while (self._running and max_cycles == None) or (max_cycles != None and _cycle < max_cycles):
			_start = dt.datetime.utcnow()

			tasks_running = 0
			for task in self._tasks:
				was_running = task.run()
				if was_running:
					tasks_running += 1
					if task.is_one_shot:
						# print('-> removing one shot task')
						self._tasks.remove(task)

				_diff = dt.datetime.utcnow() - _start
				if _diff > dt.timedelta(seconds=self.MAX_TIME):
					# print('-> Scheduler.run() exceeded max time')
					break

			if tasks_running == 0:
				_sleep_time = _sleep_time * self.IDLE_MULTIPLIER
				if _sleep_time > self.MAX_SLEEP_TIME:
					_sleep_time = self.MAX_SLEEP_TIME
				# print('-> _sleep_time', _sleep_time)
			else:
				_sleep_time = self.SLEEP_TIME

			#print('-> Scheduler sleeping: {}'.format(_sleep_time))
			time.sleep(_sleep_time)

			_cycle += 1

	def shutdown(self):
		# print('-> Scheduler.shutdown()')
		self._running = False
