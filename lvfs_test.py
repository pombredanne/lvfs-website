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
        cfgfile = open(self.cfg_filename, 'w')
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

    def _login(self, username, password):
        return self.app.post('/lvfs/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def _logout(self):
        return self.app.get('/lvfs/logout', follow_redirects=True)

    def login(self, username, password=None):
        if not password:
            if username == 'admin':
                password = 'Pa$$w0rd'
        rv = self._login(username, password)
        assert b'/lvfs/upload' in rv.data

    def logout(self):
        rv = self._logout()
        assert b'/lvfs/upload' not in rv.data

    def upload(self, filename, target='private'):
        fd = open(filename, 'rb')
        return self.app.post('/lvfs/upload', data={
            'target': target,
            'file': (fd, filename)
        }, follow_redirects=True)

    def test_login_logout(self):
        rv = self._login('admin', 'Pa$$w0rd')
        assert b'/lvfs/upload' in rv.data
        rv = self._logout()
        assert b'/lvfs/upload' not in rv.data
        rv = self._login('adminx', 'default')
        assert b'Incorrect username or password' in rv.data
        rv = self._login('admin', 'defaultx')
        assert b'Incorrect username or password' in rv.data

    def test_upload_invalid(self):
        self.login('admin')
        rv = self.upload('contrib/Dockerfile')
        assert b'Failed to upload file' in rv.data

    def test_upload_valid(self):

        # upload file
        self.login('admin')
        self.app.get('/lvfs/settings') #FIXME?
        rv = self.upload('contrib/hughski-colorhug2-2.0.3.cab')
        assert b'com.hughski.ColorHug2.firmware' in rv.data
        assert b'3d69d6c68c915d7cbb4faa029230c92933263f42' in rv.data

        # check analytics works
        uris = ['/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/analytics',
                '/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/analytics/clients',
                '/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/analytics/month',
                '/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/analytics/reports',
                '/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/analytics/year']
        for uri in uris:
            rv = self.app.get(uri)
            assert b'favicon.ico' in rv.data
            assert b'LVFS: Error' not in rv.data

        # check component view shows GUID
        rv = self.app.get('/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/component/com.hughski.ColorHug2.firmware')
        assert b'2082b5e0-7a64-478a-b1b2-e3404fab6dad' in rv.data

        # check devices page shows private firmware as admin -- and hidden when anon
        rv = self.app.get('/lvfs/device')
        assert b'2082b5e0-7a64-478a-b1b2-e3404fab6dad' in rv.data
        rv = self.app.get('/lvfs/device/2082b5e0-7a64-478a-b1b2-e3404fab6dad')
        assert b'MCDC04 errata' in rv.data
        self.logout()
        rv = self.app.get('/lvfs/device')
        assert b'2082b5e0-7a64-478a-b1b2-e3404fab6dad' not in rv.data
        rv = self.app.get('/lvfs/device/2082b5e0-7a64-478a-b1b2-e3404fab6dad')
        # FIXME is it a bug that we show the device exists even though it's not got any mds?
        assert b'MCDC04 errata' not in rv.data
        rv = self.app.get('/lvfs/devicelist')
        assert b'ColorHug' not in rv.data
        self.login('admin')

        # promote the firmware to testing then stable
        rv = self.app.get('/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/promote/testing', follow_redirects=True)
        assert b'>testing<' in rv.data
        assert b'>stable<' not in rv.data
        rv = self.app.get('/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/promote/stable', follow_redirects=True)
        assert b'>stable<' in rv.data
        assert b'>testing<' not in rv.data

        # check it's now in the devicelist as anon
        self.logout()
        rv = self.app.get('/lvfs/devicelist')
        assert b'ColorHug' in rv.data
        self.login('admin')

        # test deleting the firmware
        rv = self.app.get('/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/delete')
        assert b'Irrevocably Remove Firmware' in rv.data
        rv = self.app.get('/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/delete_force', follow_redirects=True)
        assert b'Firmware deleted' in rv.data

    def test_eventlog(self):
        #login,upload,check:
        #/lvfs/eventlog
        pass

    def test_groups(self):
        #login,upload,check:
        #/lvfs/group/hughski/admin
        #/lvfs/group/hughski/delete
        #/lvfs/grouplist
        pass

    def test_vendorlist(self):
        #login,upload,check:
        #/lvfs/vendor/hughski/delete
        #/lvfs/vendor/hughski/details
        #/lvfs/vendorlist
        pass

    def test_users(self):
        #login,upload,check:
        #/lvfs/user/hughskiqa/admin
        #/lvfs/user/hughskiqa/delete
        #/lvfs/userlist
        pass

    def test_profile(self):
        #login,change password:
        #/lvfs/profile
        pass

    def test_reports(self):
        #login,upload-fw,upload-report,check:
        #/lvfs/telemetry
        #/lvfs/report/reportid
        #/lvfs/report/reportid/delete
        pass

    def test_settings(self):
        #login,check:
        #/lvfs/settings
        #/lvfs/settings/wu-copy
        pass

    def test_updateinfo(self):
        #login,upload,change-update-info,check:
        #/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/component/com.hughski.ColorHug2.firmware/update
        pass

    def test_requires(self):
        #login,upload,check:
        #/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/component/com.hughski.ColorHug2.firmware/requires
        #/lvfs/firmware/3d69d6c68c915d7cbb4faa029230c92933263f42/component/com.hughski.ColorHug2.firmware/requires/remove/hwid/fwupd
        pass

    def test_metadata_rebuild(self):
        #login,upload,check:
        #/lvfs/metadata
        #/lvfs/metadata/hughski
        #/lvfs/metadata_rebuild
        pass

    def test_nologin_required(self):
        uris = ['/',
                '/lvfs',
                '/vendors',
                '/users',
                '/developers',
                '/privacy',
                '/status',
                '/donations',
                '/vendorlist',
                '/lvfs/newaccount',
                '/lvfs/devicelist',
                '/lvfs/device/2082b5e0-7a64-478a-b1b2-e3404fab6dad',
               ]
        for uri in uris:
            print('GET', uri)
            rv = self.app.get(uri, follow_redirects=True)
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
