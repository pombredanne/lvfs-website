#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from sqlalchemy import create_engine, func
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

def _execute_count_star(q):
    count_query = q.statement.with_only_columns([func.count()]).order_by(None)
    return q.session.execute(count_query).scalar()

class Database(object):

    def __init__(self):
        self.engine = None
        self.session = None
        self.Base = None

    def init_app(self, app):
        print('opening database %s' % app.config['DATABASE'])
        self.engine = create_engine(app.config['DATABASE'], convert_unicode=True)
        self.engine.echo = app.testing
        self.session = scoped_session(sessionmaker(autocommit=False,
                                                 autoflush=False,
                                                 bind=self.engine))
        self.Base = declarative_base()
        self.Base.query = self.session.query_property()

    def init_db(self):

        # create all tables
        self.Base.metadata.create_all(bind=self.engine)

        # ensure admin user exists
        from .models import User
        if not self.session.query(User).filter(User.username == 'admin').first():
            self.session.add(User(username='admin',
                                password='5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4',
                                display_name='Admin User',
                                email='sign-test@fwupd.org',
                                group_id='admin',
                                is_enabled=True,
                                is_qa=True,
                                is_analyst=True))
            self.session.commit()
