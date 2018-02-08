#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import sqlalchemy

from flask import Flask, flash, render_template, g
from flask_login import LoginManager
from werkzeug.local import LocalProxy

from .response import SecureResponse
from .pluginloader import Pluginloader
from .util import _error_internal

app = Flask(__name__)
if os.path.exists('app/custom.cfg'):
    app.response_class = SecureResponse
    app.config.from_pyfile('custom.cfg')
else:
    app.config.from_pyfile('flaskapp.cfg')

from .db import db_session
from .models import User

lm = LoginManager()
lm.init_app(app)

ploader = Pluginloader('plugins')

@app.teardown_appcontext
def shutdown_session(unused_exception=None):
    db_session.remove()

@lm.user_loader
def load_user(user_id):
    g.user = db_session.query(User).filter(User.username == user_id).first()
    return g.user

@app.errorhandler(404)
def error_page_not_found(msg=None):
    """ Error handler: File not found """
    flash(msg)
    return render_template('error.html'), 404

#@app.errorhandler(sqlalchemy.exc.OperationalError)
#def handle_error(error):
#    return _error_internal(str(error))

from app import views
from app import views_user
from app import views_group
from app import views_device
from app import views_firmware
from app import views_vendor
