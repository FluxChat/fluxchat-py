
from unittest import TestCase
import datetime as dt
import time

from lib.task import Task

class TaskTestCase(TestCase):
	def test_task1(self):
		task = Task(lambda: True)
		self.assertTrue(task.run())

	def test_task2(self):
		task = Task(lambda: 'ABC', dt.timedelta(minutes=1))
		self.assertEqual(task.run(), 'ABC')
		self.assertEqual(task.run(), False)

	def test_task3(self):
		task = Task(lambda: 'ABC', dt.timedelta(minutes=1), True)
		self.assertEqual(task.run(), False)
		self.assertEqual(task.run(), False)

	def test_task4(self):
		task = Task(lambda: 'ABC', dt.timedelta(milliseconds=100))
		self.assertEqual(task.run(), 'ABC')
		time.sleep(0.2)
		self.assertEqual(task.run(), 'ABC')
