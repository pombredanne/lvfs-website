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

    def login(self, username, password):
        return self.app.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.app.get('/logout', follow_redirects=True)

    def test_login_logout(self):
        rv = self.login('admin', 'P@$$w0rd')
        print(rv.data)
        assert b'You were logged in' in rv.data
        rv = self.logout()
        assert b'You were logged out' in rv.data
        rv = self.login('adminx', 'default')
        assert b'Invalid username' in rv.data
        rv = self.login('admin', 'defaultx')
        assert b'Invalid password' in rv.data

    def test_nologin_required(self):
        uris = ['/',
                '/vendors',
                '/users',
                '/developers',
                '/privacy',
                '/donations',
                '/vendorlist',
                '/lvfs/devicelist',
                '/lvfs/device/2082b5e0-7a64-478a-b1b2-e3404fab6dad',
               ]
        for uri in uris:
            print('GET', uri)
            rv = self.app.get(uri)
            assert b'favicon.ico' in rv.data
            assert b'LVFS: Error' not in rv.data

    def test_fail_when_login_required(self):
        uris = ['/lvfs/firmware']
        for uri in uris:
            print('GET', uri)
            rv = self.app.get(uri)
            assert b'favicon.ico' in rv.data
            assert b'LVFS: Error' in rv.data

if __name__ == '__main__':
    unittest.main()
