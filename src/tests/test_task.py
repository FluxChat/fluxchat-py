
import unittest
from lib.task import Task

class TaskTestCase(unittest.TestCase): # TODO: add more tests
	def test_task1(self):
		task = Task(lambda x: x)
