#!/usr/bin/python
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from __future__ import print_function

import sys
import requests

USERNAME = 'user'
PASSWORD = 'pass'
SERVER = 'https://testing-lvfs.rhcloud.com'

# check args
if len(sys.argv) != 2:
    print("File not specified")
    sys.exit(1)

# open file
filename = sys.argv[1]
try:
    f = open(filename, 'rb')
except IOError as e:
    print("File not found")
    sys.exit(1)

# upload to lvfs
payload = {'username': USERNAME,
           'password': PASSWORD}
uri = "%s?action=upload&target=testing" % SERVER
r = requests.post(uri, data=payload, files={'file': f})
if r.status_code == 201:
    print('Firmware uploaded successfully')
    sys.exit(0)
elif r.status_code == 401:
    print("Authentication failed!")
    sys.exit(1)
elif r.status_code == 422:
    print("The file already exists!")
    sys.exit(2)
else:
    print("An error occurred:", r.status_code, r.text)
    sys.exit(1)
