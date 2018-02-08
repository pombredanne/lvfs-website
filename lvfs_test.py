#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import unittest
import tempfile

class LvfsTestCase(unittest.TestCase):

    def setUp(self):

        # create new database
        self.db_fd, self.db_filename = tempfile.mkstemp()
        self.db_uri = 'sqlite:///' + self.db_filename

        # write out custom settings file
        self.cfg_filename = '/tmp/foo.cfg'
        cfgfile = open(self.cfg_filename,'w')
        cfgfile.write("DATABASE = '%s'\nTESTING = True\n" % self.db_uri)
        cfgfile.close()
        os.environ['LVFS_CUSTOM_SETTINGS'] = self.cfg_filename

        # create instance
        import app as lvfs
        from app import db
        self.app = lvfs.app.test_client()
        with lvfs.app.app_context():
            db.init_db()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_filename)
        os.unlink(self.cfg_filename)

    def login(self, username, password):
        return self.app.post('/lvfs/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.app.get('/lvfs/logout', follow_redirects=True)

    def test_login_logout(self):
        rv = self.login('admin', 'Pa$$w0rd')
        assert b'/lvfs/upload' in rv.data
        rv = self.logout()
        assert b'/lvfs/upload' not in rv.data
        rv = self.login('adminx', 'default')
        assert b'Incorrect username or password' in rv.data
        rv = self.login('admin', 'defaultx')
        assert b'Incorrect username or password' in rv.data

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
