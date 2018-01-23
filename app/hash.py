#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import hashlib

def _qa_hash(value):
    """ Generate a salted hash of the QA group """
    salt = 'vendor%%%'
    return hashlib.sha1((salt + value).encode('utf-8')).hexdigest()

def _addr_hash(value):
    """ Generate a salted hash of the IP address """
    salt = 'addr%%%'
    return hashlib.sha1((salt + value).encode('utf-8')).hexdigest()

def _password_hash(value):
    """ Generate a salted hash of the password string """
    salt = 'lvfs%%%'
    return hashlib.sha1((salt + value).encode('utf-8')).hexdigest()
