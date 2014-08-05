#!/usr/bin/env python
#
# Copyright 2014 Townsville Catholic Education Office
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Google Chrome Device Lister

This web application lists all chrome devices and their various
properties (including MAC address and OS version) in a sortable
table so an administrator can keep track of them.  There is also
a cache function so non-administrators can view those chrome
device properties.
"""

import httplib2
import logging
import os
import json
import sys
import traceback

from apiclient import discovery
from oauth2client import appengine
from oauth2client.appengine import OAuth2Decorator
from oauth2client.appengine import StorageByKeyName
from oauth2client.appengine import CredentialsModel
from oauth2client import client
from oauth2client import clientsecrets
from google.appengine.api import memcache
from google.appengine.api import users
from datetime import datetime
from datetime import date
from datetime import timedelta
from google.appengine.ext import db
from google.appengine.ext import ndb

import webapp2
import jinja2

class OAuth2ClientSecret(db.Model):
  client_type = db.StringProperty(required=True)
  auth_uri = db.StringProperty(required=True)
  client_id = db.StringProperty(required=True)
  client_secret = db.StringProperty(required=True)
  token_uri = db.StringProperty(required=True)
  redirect_uris = db.StringListProperty(required=True)
  auth_provider_x509_cert_url = db.StringProperty()
  client_email = db.StringProperty()
  client_x509_cert_url = db.StringProperty()
  javascript_origins = db.StringListProperty()
  revoke_uri = db.StringProperty()

class CustomerLink(ndb.Model):
  customerid = ndb.StringProperty(required=True)
  linkeduserid = ndb.StringProperty(required=True)

class ActiveUsersCache(ndb.Model):
  customerid = ndb.StringProperty(required=True)
  lastupdate = ndb.DateTimeProperty(required=True)
  activeusers = ndb.PickleProperty(required=True)

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    autoescape=True,
    extensions=['jinja2.ext.autoescape'])

# CLIENT_SECRETS, name of a file containing the OAuth 2.0 information for this
# application, including client_id and client_secret, which are found
# on the API Access tab on the Google APIs
# Console <http://code.google.com/apis/console>
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
CLIENT_SECRETS_NAMESPACE = "tsvceo-chrome-device-mgmt:clientsecrets#ns"

# Helpful message to display in the browser if the CLIENT_SECRETS file
# is missing.
MISSING_CLIENT_SECRETS_MESSAGE = """
<h1>Warning: Please configure OAuth 2.0</h1>
<p>
To make this sample run you will need to populate the client_secrets.json file
found at:
</p>
<p>
<code>%s</code>.
</p>
<p>with information found on the <a
href="https://code.google.com/apis/console">APIs Console</a>.
</p>
""" % CLIENT_SECRETS

client_secret = memcache.get(CLIENT_SECRETS, namespace=CLIENT_SECRETS_NAMESPACE)

if client_secret is None:
  if os.path.exists(CLIENT_SECRETS):
    client_type, client_info = clientsecrets.loadfile(CLIENT_SECRETS, memcache)
    client_secret = OAuth2ClientSecret(
        key_name = "site",
        client_type = client_type,
        auth_uri = client_info.get('auth_uri'),
        client_id = client_info.get('client_id'),
        client_secret = client_info.get('client_secret'),
        token_uri = client_info.get('token_uri'),
        redirect_uris = client_info.get('redirect_uris'),
        auth_provider_x509_cert_url = client_info.get('auth_provider_x509_cert_url'),
        client_email = client_info.get('client_email'),
        client_x509_cert_url = client_info.get('client_x509_cert_url'),
        javascript_origins = client_info.get('javascript_origins'),
        revoke_uri = client_info.get('revoke_uri')
        )
    memcache.set(CLIENT_SECRETS, client_secret, namespace=CLIENT_SECRETS_NAMESPACE)
    client_secret.put()
  else:
    client_secret = db.GqlQuery("SELECT * FROM OAuth2ClientSecret").get()
    memcache.set(CLIENT_SECRETS, client_secret, namespace=CLIENT_SECRETS_NAMESPACE)

if client_secret is None:
  decorator = appengine.oauth2decorator(message = MISSING_CLIENT_SECRETS_MESSAGE)
else:
  decorator = OAuth2Decorator(
      client_id = client_secret.client_id,
      client_secret = client_secret.client_secret,
      scope=[
        'https://www.googleapis.com/auth/admin.directory.device.chromeos',
        'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly',
        'https://www.googleapis.com/auth/admin.reports.usage.readonly',
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
      ],
      auth_uri = client_secret.auth_uri,
      token_uri = client_secret.token_uri,
      message=MISSING_CLIENT_SECRETS_MESSAGE
      )

def get_customerid(http):
  reportsservice = discovery.build('admin', 'reports_v1', http=http)
  date_7daysago = (date.today() - timedelta(7)).isoformat()
  custusage = reportsservice.customerUsageReports().get(date=date_7daysago).execute(http=http)
  return custusage['usageReports'][0]['entity']['customerId']
    
def get_customerlink(customerid, userid, http):
  customerlink = CustomerLink.query(ndb.AND(CustomerLink.customerid == customerid, CustomerLink.linkeduserid == userid)).get()
  linkkey = customerlink.key

  if customerlink is None:
    customerlink = CustomerLink(customerid = customerid, linkeduserid = userid)
    linkkey = customerlink.put()

  return linkkey

def get_active_users(customerid, http):
  cachedusers = ActiveUsersCache.query(ActiveUsersCache.customerid == customerid).get()
  if cachedusers is None or datetime.now() - cachedusers.lastupdate > timedelta(hours = 12):
    users = {}
    directoryservice = discovery.build('admin', 'directory_v1', http=http)
    userlistreq = directoryservice.users().list(customer="my_customer", orderBy="email", sortOrder="ASCENDING")

    while True:
      try:
        userlist = userlistreq.execute(http=http)
      except:
        break

      for user in userlist['users']:
        if not user['suspended']:
          users[user['primaryEmail']] = True

      if 'nextPageToken' in userlist:
        userlistreq = directoryservice.users().list_next(userlistreq, userlist)
      else:
        break

    if cachedusers is None:
      cachedusers = ActiveUsersCache(customerid = customerid)

    cachedusers.lastupdate = datetime.now()
    cachedusers.activeusers = users
    cachedusers.put()
  else:
    users = cachedusers.activeusers

  return users

def get_devices(active_users, http):
  devices = []
  directoryservice = discovery.build('admin', 'directory_v1', http=http)
  devicelistreq = directoryservice.chromeosdevices().list(customerId="my_customer", orderBy="lastSync", projection="FULL", sortOrder="DESCENDING")
  
  while True:
    try:
      devicelist = devicelistreq.execute(http=http)
    except:
      break

    for device in devicelist['chromeosdevices']:
      lastEnrollmentTime = datetime.strptime(device['lastEnrollmentTime'],'%Y-%m-%dT%H:%M:%S.%fZ') if 'lastEnrollmentTime' in device else None
      lastSync = datetime.strptime(device['lastSync'],'%Y-%m-%dT%H:%M:%S.%fZ') if 'lastSync' in device else None
      annotatedUser = device.get('annotatedUser') or ''
      userActive = users is not None and annotatedUser in active_users
      devices.append({
        'serialNumber': device['serialNumber'],
        'macAddress': ':'.join((device['macAddress'][i:i+2] if 'macAddress' in device and device['macAddress'] != '' else '??') for i in range(0,12,2)),
        'status': device['status'],
        'osVersion': device.get('osVersion') or '',
        'lastEnrollmentTime': 'Never' if lastEnrollmentTime is None else lastEnrollmentTime.strftime('%a, %d %b %Y, %H:%M UTC'),
        'lastSync': 'Never' if lastEnrollmentTime is None else lastSync.strftime('%a, %d %b %Y, %H:%M UTC'),
        'annotatedUser': annotatedUser,
        'annotatedLocation': device.get('annotatedLocation') or '',
        'notes': device.get('notes') or '',
        'deviceId': device['deviceId'],
        'userActive': "" if annotatedUser == "" else ("Yes" if userActive else "No")
        })
    
    if 'nextPageToken' in devicelist:
      devicelistreq = directoryservice.chromeosdevices().list_next(devicelistreq, devicelist)
    else:
      break

  return devices

class MainHandler(webapp2.RequestHandler):
  @decorator.oauth_required
  def get(self):
    user = users.get_current_user()

    if decorator.has_credentials():
      http = decorator.http()
      customerid = get_customerid(http)
      linkkey = get_customerlink(customerid, user.user_id(), http)

    variables = {
        'auth_url': decorator.authorize_url(),
        'has_credentials': decorator.has_credentials(),
        'customerid': customerid,
        'userid': user.user_id(),
        'linkkey': linkkey.integer_id()
        }

    template = JINJA_ENVIRONMENT.get_template('main.html')
    self.response.write(template.render(variables))

class DeviceListHandler(webapp2.RequestHandler):
  def get(self):
    devices = None
    updated = 'Never'
    linkkey = self.request.get('id')
    fetcherror = 'Key not found'

    if linkkey is not None:
      customerlink = CustomerLink.get_by_id(int(linkkey))
      if customerlink is not None:
        try:
          authstorage = StorageByKeyName(CredentialsModel, customerlink.linkeduserid, 'credentials')
          credentials = authstorage.get()
          http = httplib2.Http()
          http = credentials.authorize(http)
          authstorage.put(credentials)
          active_users = get_active_users(customerlink.customerid, http)
          devices = get_devices(active_users, http)
          updated = datetime.now().strftime('%a, %d %b %Y, %H:%M UTC')
          fetcherror = None
        except:
          fetcherror = traceback.format_exc()
    
    variables = {
        'linkkey': linkkey,
        'devices': devices,
        'updated': updated,
        'fetcherror': fetcherror
        }
    
    self.response.headers['Content-Type'] = 'application/json'
    self.response.write(json.dumps(variables))

class FetchHandler(webapp2.RequestHandler):
  def get(self):
    linkkey = self.request.get('id')
    
    variables = {
        'linkkey': linkkey
        }

    template = JINJA_ENVIRONMENT.get_template('fetch.html')
    self.response.write(template.render(variables))

class DeleteHandler(webapp2.RequestHandler):
  def get(self):
    linkkey = self.request.get('id')
    if linkkey is not None:
      customerlink = CustomerLink.get_by_id(int(linkkey))
      if customerlink is not None:
        customerlink.key.delete()
    self.redirect("/")

app = webapp2.WSGIApplication(
    [
     ('/', MainHandler),
     ('/fetch', FetchHandler),
     ('/devlist', DeviceListHandler),
     ('/delete', DeleteHandler),
     (decorator.callback_path, decorator.callback_handler()),
    ],
    debug=True)
