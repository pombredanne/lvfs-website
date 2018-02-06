#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

#from __future__ import print_function

from sqlalchemy import create_engine, func
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from app import app

engine = create_engine(app.config['DATABASE'], convert_unicode=True)
engine.echo = True
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    # create all tables
    Base.metadata.create_all(bind=engine)

    # ensure admin user exists
    from .models import User
    if not db_session.query(User).filter(User.username == 'admin').first():
        db_session.add(User(username='admin',
                            password='5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4',
                            display_name='Admin User',
                            email='sign-test@fwupd.org',
                            group_id='admin',
                            is_enabled=True,
                            is_qa=True,
                            is_analyst=True))
        db_session.commit()

def _execute_count_star(q):
    count_query = q.statement.with_only_columns([func.count()]).order_by(None)
    return q.session.execute(count_query).scalar()
