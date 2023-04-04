#!/usr/bin/env python3

import unittest
from lib.server import Server

class ServerTestCase(unittest.TestCase):
	def setUp(self):
		self.server = Server({
			'id': 'FC_test',
			'data_dir': 'tmp/'
		})

	def test_has_contact_default(self):
		self.assertFalse(self.server.has_contact())
