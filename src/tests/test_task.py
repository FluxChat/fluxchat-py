
import unittest
from lib.task import Task

class TaskTestCase(unittest.TestCase):
	def test_task1(self):
		task = Task(lambda x: x)
