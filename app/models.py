#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import datetime

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .db import Base, db_session

class UserCapability(object):
    Admin = 'admin'
    QA = 'qa'
    Analyst = 'analyst'
    User = 'user'

class User(Base):

    # database
    __tablename__ = 'users'
    username = Column(String(40), primary_key=True, nullable=False, unique=True, default='')
    password = Column(String(40), nullable=False, default='')
    display_name = Column(String(128))
    email = Column(String(255))
    group_id = Column(String(40), nullable=False)
    is_enabled = Column(Boolean, default=False)
    is_qa = Column(Boolean, default=False)
    is_analyst = Column(Boolean, default=False)
    is_locked = Column(Boolean, default=False)

    def __init__(self, username, password=None, display_name=None, email=None,
                 group_id=None, is_enabled=False, is_analyst=False, is_qa=False, is_locked=False):
        """ Constructor for object """
        self.username = username
        self.password = password
        self.display_name = display_name
        self.email = email
        self.is_enabled = is_enabled
        self.is_analyst = is_analyst
        self.is_qa = is_qa
        self.group_id = group_id
        self.is_locked = is_locked

    def check_group_id(self, group_id):

        # admin can see everything
        if self.group_id == 'admin':
            return True

        # typically used when checking if a vendor can delete firmware
        if self.group_id == group_id:
            return True

        # something else
        return False

    def check_capability(self, required_auth_level):

        # user has been disabled for bad behaviour
        if not self.is_enabled:
            return False

        # admin only
        if required_auth_level == UserCapability.Admin:
            if self.group_id == 'admin':
                return True
            return False

        # analysts only
        if required_auth_level == UserCapability.Analyst:
            if self.group_id == 'admin':
                return True
            if self.is_qa:
                return True
            if self.is_analyst:
                return True
            return False

        # QA only
        if required_auth_level == UserCapability.QA:
            if self.group_id == 'admin':
                return True
            if self.is_qa:
                return True
            return False

        # any action that just requires to be logged in
        if required_auth_level == UserCapability.User:
            return True

        # something else
        return False

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.username)

    def __repr__(self):
        return "User object %s" % self.username

class Group(Base):

    # sqlalchemy metadata
    __tablename__ = 'groups'
    group_id = Column(String(40), primary_key=True, unique=True)
    _vendor_ids = Column('vendor_ids', String(40), nullable=False, default='')

    def __init__(self, group_id=None):
        """ Constructor for object """
        self.group_id = group_id
        self._vendor_ids = ''

    @property
    def vendor_ids(self):
        return self._vendor_ids.split(',')

    @vendor_ids.setter
    def set_vendor_ids(self, value):
        self._vendor_ids = ','.join(value)

    def __repr__(self):
        return "Group object %s" % self.group_id

class Vendor(Base):

    # sqlalchemy metadata
    __tablename__ = 'vendors'
    group_id = Column(String(40), primary_key=True, nullable=False, unique=True, default='')
    display_name = Column(String(128), nullable=False, default='')
    plugins = Column(String(128), nullable=False, default='')
    description = Column(String(255), nullable=False, default='')
    visible = Column(Boolean, default=False)
    is_fwupd_supported = Column(String(16), nullable=False, default='no')
    is_account_holder = Column(String(16), nullable=False, default='no')
    is_uploading = Column(String(16), nullable=False, default='no')
    comments = Column(String(255), nullable=False, default='')

    def __init__(self, group_id=None):
        """ Constructor for object """
        self.group_id = group_id
        self.display_name = None
        self.plugins = None
        self.description = None
        self.visible = False
        self.is_fwupd_supported = None
        self.is_account_holder = None
        self.is_uploading = None
        self.comments = None

    def _get_sorting_key(self):
        val = 0
        if self.is_fwupd_supported == 'yes':
            val += 0x200
        if self.is_fwupd_supported == 'na':
            val += 0x100
        if self.is_account_holder == 'yes':
            val += 0x20
        if self.is_account_holder == 'na':
            val += 0x10
        if self.is_uploading == 'yes':
            val += 0x2
        if self.is_uploading == 'na':
            val += 0x1
        return val
    def __repr__(self):
        return "Vendor object %s" % self.group_id

class EventLogItem(Base):

    # sqlalchemy metadata
    __tablename__ = 'event_log'
    id = Column(Integer, primary_key=True, nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    username = Column(String(40), nullable=False, default='')
    group_id = Column(String(40), nullable=False)
    address = Column('addr', String(40), nullable=False)
    message = Column(Text)
    is_important = Column(Integer, default=0)
    request = Column(Text)

    def __init__(self, username=None, group_id=None, address=None, message=None,
                 request=None, is_important=False):
        """ Constructor for object """
        self.timestamp = None
        self.username = username
        self.group_id = group_id
        self.address = address
        self.message = message
        self.request = request
        self.is_important = is_important
    def __repr__(self):
        return "EventLogItem object %s" % self.message

class FirmwareRequirement(object):
    def __init__(self, kind=None, value=None, compare=None, version=None):
        """ Constructor for object """
        self.kind = kind        # e.g. 'id', 'firmware' or 'hardware'
        self.value = value      # e.g. 'bootloader' or 'org.freedesktop.fwupd'
        self.compare = compare
        self.version = version
    def to_string(self):
        return "%s/%s/%s/%s" % (self.kind, self.value, self.compare, self.version)
    def from_string(self, txt):
        tmp = txt.split('/')
        if len(tmp) != 4:
            return
        self.kind = tmp[0]
        self.value = tmp[1]
        self.compare = tmp[2]
        self.version = tmp[3]
    def __eq__(self, other):
        return self.kind == other.kind and \
                    self.value == other.value and \
                    self.compare == other.compare and \
                    self.version == other.version
    def __repr__(self):
        return "FirmwareRequirement object %s" % self.kind

class FirmwareMd(Base):

    # sqlalchemy metadata
    __tablename__ = 'firmware_md'
    metainfo_id = Column(String(40), primary_key=True, nullable=False)
    firmware_id = Column(String(40), ForeignKey('firmware.firmware_id'), primary_key=True, nullable=False)
    checksum_contents = Column(String(40), nullable=False)
    checksum_container = Column(String(40), nullable=False)
    cid = Column('id', Text)
    name = Column(Text)
    summary = Column(Text)
    guid = Column(Text)
    description = Column(Text)
    release_description = Column(Text)
    url_homepage = Column(Text)
    metadata_license = Column(Text)
    project_license = Column(Text)
    developer_name = Column(Text)
    filename_contents = Column(Text)
    release_timestamp = Column(Integer, default=0)
    version = Column(String(255))
    release_installed_size = Column(Integer, default=0)
    release_download_size = Column(Integer, default=0)
    release_urgency = Column(String(16))
    screenshot_url = Column(Text)
    screenshot_caption = Column(Text)
    requirements = Column(Text)

    # link back to parent
    fw = relationship("Firmware", back_populates="mds")

    # create indexes
    #Index('id', 'firmware_id', 'metainfo_id', unique=True)

    @property
    def guids(self):
        return self.guid.split(',')

    @guids.setter
    def guids(self, value):
        self.guid = ','.join(value)

    def __init__(self):
        """ Constructor for object """
        self.firmware_id = None             # this maps the object back to Firmware
        self.cid = None                     # e.g. com.hughski.ColorHug.firmware
        self.guids = []
        self.version = None
        self.name = None
        self.summary = None
        self.checksum_contents = None       # SHA1 of the firmware.bin
        self.release_description = None
        self.release_timestamp = 0
        self.developer_name = None
        self.metadata_license = None
        self.project_license = None
        self.url_homepage = None
        self.description = None
        self.checksum_container = None      # SHA1 of the signed .cab: FIXME: move
        self.filename_contents = None       # filename of the firmware.bin
        self.release_installed_size = 0
        self.release_download_size = 0
        self.release_urgency = None
        self.screenshot_url = None
        self.screenshot_caption = None
        self.requirements = []              # requirements, e.g. "id/fwupd/ge/0.8.2"
        self.metainfo_id = None             # SHA1 of the metainfo.xml file

    @property
    def requirements(self):
        reqs = []
        for fwreq_str in self.requirements.split(','):
            fwreq = FirmwareRequirement()
            fwreq.from_string(fwreq_str)
            reqs.append(fwreq)
        return reqs

    @requirements.setter
    def requirements(self, value):
        reqstrs = []
        for fwreq in value:
            reqstrs.append(fwreq.to_string)
        return ','.join(reqstrs)

    def find_fwreq(self, kind=None, value=None):
        """ Find a FirmwareRequirement from the kind and/or value """
        for fwreq in self.requirements:
            if kind and fwreq.kind != kind:
                continue
            if value and fwreq.value != value:
                continue
            return fwreq
        return None

    def __repr__(self):
        return "FirmwareMd object %s" % self.firmware_id

class Firmware(Base):

    # sqlalchemy metadata
    __tablename__ = 'firmware'
    group_id = Column(String(40), nullable=False)
    addr = Column(String(40), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    filename = Column(String(255), nullable=False)
    download_cnt = Column(Integer, default=0)
    firmware_id = Column(String(40), primary_key=True, unique=True)
    version_display = Column(String(255), nullable=True, default=None)
    target = Column(String(255), nullable=False)

    # include all FirmwareMd objects
    mds = relationship("FirmwareMd", back_populates="fw")

    def __init__(self):
        """ Constructor for object """
        self.group_id = None
        self.addr = None
        self.timestamp = None
        self.filename = None        # filename of the original .cab file
        self.firmware_id = None     # SHA1 of the original .cab file
        self.target = None          # pivate, embargo, testing, etc.
        self.version_display = None # from the firmware.inf file
        self.download_cnt = 0       # generated from the client database
        self.mds = []

    def __repr__(self):
        return "Firmware object %s" % self.firmware_id

class Client(Base):

    # sqlalchemy metadata
    __tablename__ = 'clients'
    id = Column(Integer, primary_key=True, nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    addr = Column(String(40), nullable=False)
    filename = Column(String(256), index=True)
    user_agent = Column(String(256), default=None)

    def __init__(self, addr=None, filename=None, user_agent=None, timestamp=None):
        """ Constructor for object """
        self.id = 0
        self.timestamp = timestamp
        self.addr = addr
        self.filename = filename
        self.user_agent = user_agent

    def __repr__(self):
        return "Client object %s" % self.id

class Report(Base):

    # sqlalchemy metadata
    __tablename__ = 'reports'
    id = Column(Integer, primary_key=True, nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    state = Column(Integer, default=0)
    json = Column(Text)
    machine_id = Column(String(64), nullable=False)
    firmware_id = Column(String(40), nullable=False)
    checksum = Column(String(64), nullable=False)

    def __init__(self, firmware_id=None, machine_id=None, state=0, checksum=None, json=None):
        """ Constructor for object """
        self.id = 0
        self.timestamp = None
        self.state = state
        self.json = json
        self.machine_id = machine_id
        self.firmware_id = firmware_id
        self.checksum = checksum
    def __repr__(self):
        return "Report object %s" % self.id

class Setting(Base):

    # sqlalchemy metadata
    __tablename__ = 'settings'
    key = Column('config_key', Text, primary_key=True)
    value = Column('config_value', Text)

    def __init__(self, key, value=None):
        """ Constructor for object """
        self.key = key
        self.value = value
    def __repr__(self):
        return "Setting object %s" % self.key

def _get_datestr_from_datetime(when):
    return int("%04i%02i%02i" % (when.year, when.month, when.day))

class Analytic(Base):

    # sqlalchemy metadata
    __tablename__ = 'analytics'
    datestr = Column(Integer, primary_key=True, default=0)
    kind = Column(Integer, primary_key=True, default=0)
    cnt = Column(Integer, default=1)
    #Index('datestr', 'kind', unique=True)

    def __init__(self, kind, timestamp=datetime.date.today()):
        """ Constructor for object """
        self.kind = kind
        self.cnt = 1
        self.datestr = _get_datestr_from_datetime(timestamp)

    def __repr__(self):
        return "Analytic object %i:%s" % (self.kind, self.datestr)

class DownloadKind(object):
    METADATA = 0
    FIRMWARE = 1
    SIGNING = 2
