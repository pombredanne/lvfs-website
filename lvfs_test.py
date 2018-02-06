#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import unittest
import tempfile

import app as lvfs
from app.db import init_db

class LvfsTestCase(unittest.TestCase):

    def setUp(self):
        self.db_fd, lvfs.app.config['DATABASE_FN'] = tempfile.mkstemp()
        lvfs.app.config['DATABASE'] = 'sqlite:///' + lvfs.app.config['DATABASE_FN']
        lvfs.app.testing = True
        self.app = lvfs.app.test_client()
        with lvfs.app.app_context():
            init_db()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(lvfs.app.config['DATABASE_FN'])

    def test_empty_db(self):
        rv = self.app.get('/vendors')
        assert b'No entries here so far' in rv.data

if __name__ == '__main__':
    unittest.main()
