#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from __future__ import print_function

import os
import datetime
import hashlib
import math
import configparser

from gi.repository import AppStreamGlib
from gi.repository import GCab
from gi.repository import Gio
from gi.repository import GLib

from flask import session, request, flash, url_for, redirect, render_template, Response
from flask import send_from_directory, abort, make_response
from flask_login import login_required, login_user, logout_user

from app import app, db, lm, ploader

from .db import CursorError
from .models import Firmware, FirmwareMd, FirmwareRequirement, DownloadKind
from .foreign_archive import _repackage_archive
from .inf_parser import InfParser
from .hash import _qa_hash, _password_hash
from .util import _event_log, _get_client_address
from .util import _error_internal, _error_permission_denied
from .util import _archive_get_files_from_glob
from .util import _get_chart_labels_months, _get_chart_labels_days
from .metadata import _metadata_update_group, _metadata_update_targets, _metadata_update_pulp

def _check_session():
    if 'username' not in session:
        return False
    if 'group_id' not in session:
        return False
    if 'qa_capability' not in session:
        return False
    if 'is_locked' not in session:
        return False
    return True

################################################################################

@app.route('/<path:resource>')
def serveStaticResource(resource):
    """ Return a static image or resource """

    # ban MJ12BOT, it ignores robots.txt
    user_agent = request.headers.get('User-Agent')
    if user_agent and user_agent.find('MJ12BOT') != -1:
        abort(403)

    # log certain kinds of files
    if resource.endswith('.cab'):
        try:
            db.clients.add(datetime.date.today(), DownloadKind.FIRMWARE)
            db.clients.increment(_get_client_address(),
                                 os.path.basename(resource),
                                 user_agent)
        except CursorError as e:
            print(str(e))

    # firmware blobs
    if resource.startswith('downloads/'):
        return send_from_directory(app.config['DOWNLOAD_DIR'], os.path.basename(resource))

    # static files served locally
    return send_from_directory(os.path.join(app.root_path, 'static'), resource)

@app.context_processor
def utility_processor():

    def format_truncate(tmp, length):
        if len(tmp) <= length:
            return tmp
        return tmp[:length] + u'…'

    def format_timestamp(tmp):
        if not tmp:
            return 'n/a'
        return datetime.datetime.fromtimestamp(tmp).strftime('%Y-%m-%d %H:%M:%S')

    def format_size(num, suffix='B'):
        if type(num) not in (int, long):
            return "???%s???" % num
        for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
            if abs(num) < 1024.0:
                return "%3.1f%s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f%s%s" % (num, 'Yi', suffix)

    def format_qa_hash(tmp):
        return _qa_hash(tmp)

    return dict(format_size=format_size,
                format_truncate=format_truncate,
                format_qa_hash=format_qa_hash,
                format_timestamp=format_timestamp)

@lm.unauthorized_handler
def unauthorized():
    msg = ''
    if request.url:
        msg += 'Tried to request %s' % request.url
    if request.user_agent:
        msg += ' from %s' % request.user_agent
    return _error_permission_denied(msg)

@app.errorhandler(401)
def errorhandler_401(msg=None):
    print("generic error handler")
    return _error_permission_denied(msg)

@app.route('/developers')
def developers():
    return render_template('developers.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/users')
def users():
    return render_template('users.html')

@app.route('/donations')
def donations():
    return render_template('donations.html')

@app.route('/vendors')
def vendors():
    return render_template('vendors.html')

@app.route('/')
@app.route('/lvfs/')
def index():
    user = db.users.get_item('admin')
    settings = db.settings.get_all()
    default_admin_password = False
    if user and user.password == '5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4':
        default_admin_password = True
    return render_template('index.html',
                           server_warning=settings['server_warning'],
                           default_admin_password=default_admin_password)

@app.route('/lvfs/newaccount')
def new_account():
    """ New account page for prospective vendors """
    return render_template('new-account.html')

@login_required
@app.route('/lvfs/metadata/<qa_group>')
def metadata_remote(qa_group):
    """
    Generate a remote file for a given QA group.
    """

    # find the Group
    try:
        item = db.groups.get_item(qa_group)
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal('No QA Group')

    # generate file
    remote = []
    remote.append('[fwupd Remote]')
    remote.append('Enabled=true')
    remote.append('Title=Embargoed for ' + qa_group)
    remote.append('Keyring=gpg')
    remote.append('MetadataURI=https://fwupd.org/downloads/firmware-' + _qa_hash(qa_group) + '.xml.gz')
    remote.append('OrderBefore=lvfs,fwupd')
    fn = qa_group + '-embargo.conf'
    response = make_response('\n'.join(remote))
    response.headers['Content-Disposition'] = 'attachment; filename=' + fn
    response.mimetype = 'text/plain'
    return response

@app.route('/lvfs/metadata')
@login_required
def metadata():
    """
    Show all metadata available to this user.
    """

    # show all embargo metadata URLs when admin user
    group_ids = []
    if session['group_id'] == 'admin':
        try:
            groups = db.groups.get_all()
            for group in groups:
                group_ids.append(group.group_id)
        except CursorError as e:
            return _error_internal(str(e))
    else:
        group_ids.append(session['group_id'])
    return render_template('metadata.html',
                           group_id=session['group_id'],
                           group_ids=group_ids)

@app.route('/lvfs/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """ Upload a .cab file to the LVFS service """

    # only accept form data
    if request.method != 'POST':
        if 'username' not in session:
            return redirect(url_for('.index'))
        vendor_ids = []
        try:
            item = db.groups.get_item(session['group_id'])
        except CursorError as e:
            return _error_internal(str(e))
        if item:
            vendor_ids.extend(item.vendor_ids)
        return render_template('upload.html', vendor_ids=vendor_ids)

    # not correct parameters
    if not 'target' in request.form:
        return _error_internal('No target')
    if not 'file' in request.files:
        return _error_internal('No file')

    # can the user upload directly to stable
    if request.form['target'] in ['stable', 'testing']:
        if not session['qa_capability']:
            return _error_permission_denied('Unable to upload to this target as not QA user')

    # check size < 50Mb
    fileitem = request.files['file']
    if not fileitem:
        return _error_internal('No file object')
    data = fileitem.read()
    if len(data) > 50000000:
        flash('File too large, limit is 50Mb', 'danger')
        return redirect(request.url)
    if len(data) == 0:
        flash('File has no content', 'danger')
        return redirect(request.url)
    if len(data) < 1024:
        flash('File too small, mimimum is 1k', 'danger')
        return redirect(request.url)

    # check the file does not already exist
    firmware_id = hashlib.sha1(data).hexdigest()
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if item:
        flash('A firmware file with hash %s already exists' % firmware_id, 'danger')
        return redirect('/lvfs/firmware/%s' % item.firmware_id)

    # parse the file
    try:
        if fileitem.filename.endswith('.cab'):
            istream = Gio.MemoryInputStream.new_from_bytes(GLib.Bytes.new(data))
            arc = GCab.Cabinet.new()
            arc.load(istream)
            arc.extract(None)
        else:
            arc = _repackage_archive(fileitem.filename, data)
    except NotImplementedError as e:
        flash('Invalid file type: %s' % str(e), 'danger')
        return redirect(request.url)

    # check .inf exists
    fw_version_inf = None
    fw_version_display_inf = None
    for cf in _archive_get_files_from_glob(arc, '*.inf'):
        contents = cf.get_bytes().get_data().decode('utf-8', 'ignore')
        if contents.find('FIXME') != -1:
            flash('The inf file was not complete; Any FIXME text must be '
                  'replaced with the correct values.', 'danger')
            return redirect(request.url)

        # check .inf file is valid
        cfg = InfParser()
        cfg.read_data(contents)
        try:
            tmp = cfg.get('Version', 'Class')
        except (configparser.NoOptionError, configparser.NoSectionError) as e:
            flash('The inf file Version:Class was missing', 'danger')
            return redirect(request.url)
        if tmp != 'Firmware':
            flash('The inf file Version:Class was invalid', 'danger')
            return redirect(request.url)
        try:
            tmp = cfg.get('Version', 'ClassGuid')
        except configparser.NoOptionError as e:
            flash('The inf file Version:ClassGuid was missing', 'danger')
            return redirect(request.url)
        if tmp != '{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}':
            flash('The inf file Version:ClassGuid was invalid', 'danger')
            return redirect(request.url)
        try:
            tmp = cfg.get('Version', 'DriverVer')
            fw_version_display_inf = tmp.split(',')
            if len(fw_version_display_inf) != 2:
                flash('The inf file Version:DriverVer was invalid', 'danger')
                return redirect(request.url)
        except configparser.NoOptionError as e:
            pass

        # this is optional, but if supplied must match the version in the XML
        # -- also note this will not work with multi-firmware .cab files
        try:
            fw_version_inf = cfg.get('Firmware_AddReg', 'HKR->FirmwareVersion')
            if fw_version_inf.startswith('0x'):
                fw_version_inf = str(int(fw_version_inf[2:], 16))
            if fw_version_inf == '0':
                fw_version_inf = None
        except (configparser.NoOptionError, configparser.NoSectionError) as e:
            pass

    # check metainfo exists
    cfs = _archive_get_files_from_glob(arc, '*.metainfo.xml')
    if len(cfs) == 0:
        flash('The firmware file had no .metadata.xml files', 'danger')
        return redirect(request.url)

    # parse each MetaInfo file
    apps = []
    for cf in cfs:
        component = AppStreamGlib.App.new()
        try:
            component.parse_data(cf.get_bytes(), AppStreamGlib.AppParseFlags.NONE)
            fmt = AppStreamGlib.Format.new()
            fmt.set_kind(AppStreamGlib.FormatKind.METAINFO)
            component.add_format(fmt)
            component.validate(AppStreamGlib.AppValidateFlags.NONE)
        except GLib.Error as e:
            flash('The metadata %s could not be parsed: %s' % (cf, str(e)), 'danger')
            return redirect(request.url)

        # get the metadata ID
        contents = cf.get_bytes().get_data()
        component.add_metadata('metainfo_id', hashlib.sha1(contents).hexdigest())

        # check the file does not have any missing request.form
        if contents.decode('utf-8', 'ignore').find('FIXME') != -1:
            flash('The metadata file was not complete; '
                  'Any FIXME text must be replaced with the correct values.',
                  'danger')
            return redirect(request.url)

        # check the firmware provides something
        if len(component.get_provides()) == 0:
            flash('The metadata file did not provide any GUID.', 'danger')
            return redirect(request.url)
        release_default = component.get_release_default()
        if not release_default:
            flash('The metadata file did not provide any releases.', 'danger')
            return redirect(request.url)

        # fix up hex value
        release_version = release_default.get_version()
        if release_version.startswith('0x'):
            release_version = str(int(release_version[2:], 16))
            release_default.set_version(release_version)

        # check the inf file matches up with the .xml file
        if fw_version_inf and fw_version_inf != release_version:
            flash('The inf Firmware_AddReg[HKR->FirmwareVersion] '
                  '%s did not match the metainfo.xml value %s.'
                  % (fw_version_inf, release_version), 'danger')
            return redirect(request.url)

        # check the guid and version does not already exist
        provides_value = component.get_provides()[0].get_value()
        try:
            items = db.firmware.get_all()
        except CursorError as e:
            return _error_internal(str(e))
        for item in items:
            for md in item.mds:
                for guid in md.guids:
                    if guid == provides_value and md.version == release_version:
                        flash('A firmware file for version %s already exists' % release_version, 'danger')
                        return redirect('/lvfs/firmware/%s' % item.firmware_id)

        # check if the file dropped a GUID previously supported
        new_guids = []
        for prov in component.get_provides():
            if prov.get_kind() != AppStreamGlib.ProvideKind.FIRMWARE_FLASHED:
                continue
            new_guids.append(prov.get_value())
        for item in items:
            for md in item.mds:
                if md.cid != component.get_id():
                    continue
                for old_guid in md.guids:
                    if not old_guid in new_guids:
                        flash('Firmware %s dropped a GUID previously '
                              'supported %s' % (md.cid, old_guid), 'danger')
                        return redirect(request.url)

        # check the file didn't try to add it's own <require> on vendor-id
        # to work around the vendor-id security checks in fwupd
        req = component.get_require_by_value(AppStreamGlib.RequireKind.FIRMWARE, 'vendor-id')
        if req:
            flash('Firmware cannot specify vendor-id', 'danger')
            return redirect(request.url)

        # add to array
        apps.append(component)

    # only save if we passed all tests
    basename = os.path.basename(fileitem.filename)
    new_filename = firmware_id + '-' + basename.replace('.zip', '.cab')

    # fix up the checksums and add the detached signature
    for component in apps:

        # ensure there's always a container checksum
        release = component.get_release_default()
        csum = release.get_checksum_by_target(AppStreamGlib.ChecksumTarget.CONTENT)
        if not csum:
            csum = AppStreamGlib.Checksum.new()
            csum.set_target(AppStreamGlib.ChecksumTarget.CONTENT)
            csum.set_filename('firmware.bin')
            release.add_checksum(csum)

        # get the contents checksum
        cfs = _archive_get_files_from_glob(arc, csum.get_filename())
        if not cfs:
            flash('No %s found in the archive' % csum.get_filename(), 'danger')
            return redirect(request.url)
        contents = cfs[0].get_bytes().get_data()
        csum.set_kind(GLib.ChecksumType.SHA1)
        csum.set_value(hashlib.sha1(contents).hexdigest())

        # set the sizes
        release.set_size(AppStreamGlib.SizeKind.INSTALLED, len(contents))
        release.set_size(AppStreamGlib.SizeKind.DOWNLOAD, len(data))

        # allow plugins to sign files in the archive too
        ploader.archive_sign(arc, cfs[0])

    # export the new archive and get the checksum
    ostream = Gio.MemoryOutputStream.new_resizable()
    arc.write_simple(ostream)
    cab_data = Gio.MemoryOutputStream.steal_as_bytes(ostream).get_data()
    checksum_container = hashlib.sha1(cab_data).hexdigest()

    # dump to a file
    download_dir = app.config['DOWNLOAD_DIR']
    if not os.path.exists(download_dir):
        os.mkdir(download_dir)
    fn = os.path.join(download_dir, new_filename)
    open(fn, 'wb').write(cab_data)

    # inform the plugin loader
    ploader.file_modified(fn)

    # create parent firmware object
    target = request.form['target']
    fwobj = Firmware()
    fwobj.group_id = session['group_id']
    fwobj.addr = _get_client_address()
    fwobj.filename = new_filename
    fwobj.firmware_id = firmware_id
    fwobj.target = target
    if fw_version_display_inf:
        fwobj.version_display = fw_version_display_inf[1]

    # create child metadata object for the component
    for component in apps:
        md = FirmwareMd()
        md.firmware_id = firmware_id
        md.metainfo_id = component.get_metadata_item('metainfo_id')
        md.cid = component.get_id()
        md.name = component.get_name()
        md.summary = component.get_comment()
        md.developer_name = component.get_developer_name()
        md.metadata_license = component.get_metadata_license()
        md.project_license = component.get_project_license()
        md.url_homepage = component.get_url_item(AppStreamGlib.UrlKind.HOMEPAGE)
        md.description = component.get_description()
        md.checksum_container = checksum_container

        # from the provide
        for prov in component.get_provides():
            if prov.get_kind() != AppStreamGlib.ProvideKind.FIRMWARE_FLASHED:
                continue
            md.guids.append(prov.get_value())

        # from the release
        rel = component.get_release_default()
        md.version = rel.get_version()
        md.release_description = rel.get_description()
        md.release_timestamp = rel.get_timestamp()
        md.release_installed_size = rel.get_size(AppStreamGlib.SizeKind.INSTALLED)
        md.release_download_size = rel.get_size(AppStreamGlib.SizeKind.DOWNLOAD)
        md.release_urgency = AppStreamGlib.urgency_kind_to_string(rel.get_urgency())

        # from requires
        for req in component.get_requires():
            fwreq = FirmwareRequirement(AppStreamGlib.Require.kind_to_string(req.get_kind()),
                                        req.get_value(),
                                        AppStreamGlib.Require.compare_from_string(req.get_compare()),
                                        req.get_version())
            md.requirements.append(fwreq)

        # from the first screenshot
        if len(component.get_screenshots()) > 0:
            ss = component.get_screenshots()[0]
            if ss.caption:
                md.screenshot_caption = ss.caption
            if len(ss.images) > 0:
                im = ss.images[0]
                if im.url:
                    md.screenshot_url = im.url

        # from the content checksum
        csum = rel.get_checksum_by_target(AppStreamGlib.ChecksumTarget.CONTENT)
        md.checksum_contents = csum.get_value()
        md.filename_contents = csum.get_filename()

        fwobj.mds.append(md)

    # add to database
    try:
        db.firmware.add(fwobj)
    except CursorError as e:
        return _error_internal(str(e))
    # set correct response code
    _event_log("Uploaded file %s to %s" % (new_filename, target))

    # ensure up to date
    try:
        if target == 'embargo':
            _metadata_update_group(fwobj.group_id)
        if target == 'stable':
            _metadata_update_targets(['stable', 'testing'])
        elif target == 'testing':
            _metadata_update_targets(['testing'])
    except CursorError as e:
        return _error_internal('Failed to generate metadata: ' + str(e))

    return redirect(url_for('.firmware_show', firmware_id=firmware_id))

@app.route('/lvfs/analytics')
@app.route('/lvfs/analytics/month')
@login_required
def analytics_month():
    """ A analytics screen to show information about users """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view analytics')
    labels_days = _get_chart_labels_days()[::-1]
    data_days = db.clients.get_stats_for_month(DownloadKind.FIRMWARE)[::-1]
    return render_template('analytics-month.html',
                           labels_days=labels_days,
                           data_days=data_days)

@app.route('/lvfs/analytics/year')
@login_required
def analytics_year():
    """ A analytics screen to show information about users """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view analytics')
    labels_months = _get_chart_labels_months()[::-1]
    data_months = db.clients.get_stats_for_year(DownloadKind.FIRMWARE)[::-1]
    return render_template('analytics-year.html',
                           labels_months=labels_months,
                           data_months=data_months)

@app.route('/lvfs/analytics/user_agent')
@login_required
def analytics_user_agents():
    """ A analytics screen to show information about users """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view analytics')
    labels_user_agent, data_user_agent = db.clients.get_user_agent_stats()
    return render_template('analytics-user-agent.html',
                           labels_user_agent=labels_user_agent,
                           data_user_agent=data_user_agent)

@app.route('/lvfs/analytics/clients')
@login_required
def analytics_clients():
    """ A analytics screen to show information about users """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view analytics')
    clients = db.clients.get_all(limit=25)
    return render_template('analytics-clients.html', clients=clients)

@app.route('/lvfs/analytics/reports')
@login_required
def analytics_reports():
    """ A analytics screen to show information about users """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view analytics')
    try:
        reports = db.reports.get_all(limit=25)
    except CursorError as e:
        return _error_internal(str(e))
    return render_template('analytics-reports.html', reports=reports)

@app.route('/lvfs/report/<report_id>')
@login_required
def report_view(report_id):
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view report')
    try:
        # remove it if it already exists
        item = db.reports.find_by_id(report_id)
        if not item:
            return _error_permission_denied('Report does not exist')
    except CursorError as e:
        return _error_internal(str(e))
    return Response(response=item.json,
                    status=400, \
                    mimetype="application/json")

@app.route('/lvfs/report/<report_id>/delete')
@login_required
def report_delete(report_id):
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view report')
    try:
        db.reports.remove_by_id(report_id)
    except CursorError as e:
        return _error_internal(str(e))
    return redirect(url_for('.analytics_reports'))

@app.route('/lvfs/login', methods=['POST'])
def login():
    """ A login screen to allow access to the LVFS main page """
    # auth check
    user = None
    password = _password_hash(request.form['password'])
    try:
        user = db.users.get_item(request.form['username'],
                                 password)
    except CursorError as e:
        return _error_internal(str(e))
    if not user:
        # log failure
        _event_log('Failed login attempt for %s' % request.form['username'])
        flash('Incorrect username or password', 'danger')
        return redirect(url_for('.index'))
    if not user.is_enabled:
        # log failure
        _event_log('Failed login attempt for %s (user disabled)' % request.form['username'])
        flash('User account is disabled', 'danger')
        return redirect(url_for('.index'))

    # this is signed, not encrypted
    session['username'] = user.username
    session['qa_capability'] = user.is_qa
    session['group_id'] = user.group_id
    session['is_locked'] = user.is_locked
    login_user(user, remember=False)

    # log success
    _event_log('Logged on')
    return redirect(url_for('.index'))

@app.route('/lvfs/logout')
def logout():
    # remove the username from the session
    session.pop('username', None)
    logout_user()
    return redirect(url_for('.index'))

@app.route('/lvfs/eventlog')
@app.route('/lvfs/eventlog/<start>')
@app.route('/lvfs/eventlog/<start>/<length>')
@login_required
def eventlog(start=0, length=20):
    """
    Show an event log of user actions.
    """
    # security check
    if not session['qa_capability']:
        return _error_permission_denied('Unable to show event log for non-QA user')

    # get the page selection correct
    if session['group_id'] == 'admin':
        eventlog_len = db.eventlog.size()
    else:
        eventlog_len = db.eventlog.size_for_group_id(session['group_id'])
    nr_pages = int(math.ceil(eventlog_len / float(length)))

    # table contents
    try:
        if session['group_id'] == 'admin':
            items = db.eventlog.get_all(int(start), int(length))
        else:
            items = db.eventlog.get_all_for_group_id(session['group_id'], int(start), int(length))
    except CursorError as e:
        return _error_internal(str(e))
    if len(items) == 0:
        return _error_internal('No event log available!')

    # limit this to keep the UI sane
    if nr_pages > 20:
        nr_pages = 20

    html = ''
    for i in range(nr_pages):
        if int(start) == i * int(length):
            html += '%i ' % (i + 1)
        else:
            html += '<a href="/lvfs/eventlog/%i/%s">%i</a> ' % (i * int(length), int(length), i + 1)
    return render_template('eventlog.html', events=items, pagination_footer=html)

@app.route('/lvfs/profile')
@login_required
def profile():
    """
    Allows the normal user to change details about the account,
    """

    # security check
    if session['is_locked']:
        return _error_permission_denied('Unable to view profile as account locked')

    # auth check
    try:
        item = db.users.get_item(session['username'])
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal('Invalid username query')

    # add defaults
    if not item.display_name:
        item.display_name = "Example Name"
    if not item.email:
        item.email = "info@example.com"
    return render_template('profile.html',
                           vendor_name=item.display_name,
                           contact_email=item.email)

@app.route('/lvfs/settings')
@login_required
def settings():
    """
    Allows the admin to change details about the LVFS instance
    """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Only admin is allowed to change settings')

    # get all settings
    try:
        settings = db.settings.get_all()
        plugins = ploader.get_all()
    except CursorError as e:
        return _error_internal(str(e))
    return render_template('settings.html',
                           settings=settings,
                           plugins=plugins)

@app.route('/lvfs/settings/modify', methods=['GET', 'POST'])
@login_required
def settings_modify():
    """ Change details about the instance """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.index'))

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Unable to modify settings as non-admin')

    # not enough data
    keys = ['server_warning', 'firmware_baseuri']
    for p in ploader.get_all():
        for s in p.settings():
            keys.append(s.key)
    for key in keys:
        if key not in request.form:
            return _error_internal('no key %s in form data' % key)

    # save new values
    try:
        for key in keys:
            db.settings.modify(key, request.form[key])
    except CursorError as e:
        return _error_internal(str(e))
    _event_log('Changed server settings')
    flash('Updated settings', 'info')
    return redirect(url_for('.settings'))

@app.route('/lvfs/metadata_rebuild')
@login_required
def metadata_rebuild():
    """
    Forces a rebuild of all metadata.
    """

    # security check
    if session['group_id'] != 'admin':
        return _error_permission_denied('Only admin is allowed to force-rebuild metadata')

    # update metadata
    try:
        for group in db.groups.get_all():
            _metadata_update_group(group.group_id)
        _metadata_update_targets(['stable', 'testing'])
        _metadata_update_pulp()
    except CursorError as e:
        return _error_internal('Failed to generate metadata: ' + str(e))
    return redirect(url_for('.metadata'))
