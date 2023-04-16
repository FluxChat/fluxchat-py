
import unittest
import datetime as dt
from lib.scheduler import Scheduler

class SchedulerTestCase(unittest.TestCase):
	def task1(self) -> bool:
		return True

	def test_scheduler1(self):
		scheduler = Scheduler()
		scheduler.add_task(self.task1, interval=dt.timedelta(seconds=1))
		scheduler.add_task(self.task1, one_shot=True)
		scheduler.run(2)
		scheduler.shutdown()
