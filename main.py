#!/usr/bin/env python
#
# Copyright 2013 Google Inc.
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
"""Starting template for Google App Engine applications.

Use this project as a starting point if you are just beginning to build a Google
App Engine project. Remember to download the OAuth 2.0 client secrets which can
be obtained from the Developer Console <https://code.google.com/apis/console/>
and save them as 'client_secrets.json' in the project directory.
"""

import httplib2
import logging
import os
import json

from apiclient import discovery
from oauth2client import appengine
from oauth2client import client
from google.appengine.api import memcache
from datetime import datetime
from datetime import date
from datetime import timedelta

import webapp2
import jinja2


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    autoescape=True,
    extensions=['jinja2.ext.autoescape'])

# CLIENT_SECRETS, name of a file containing the OAuth 2.0 information for this
# application, including client_id and client_secret, which are found
# on the API Access tab on the Google APIs
# Console <http://code.google.com/apis/console>
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')

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

http = httplib2.Http(memcache)
decorator = appengine.oauth2decorator_from_clientsecrets(
    CLIENT_SECRETS,
    scope=[
      'https://www.googleapis.com/auth/admin.directory.device.chromeos',
      'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly',
      'https://www.googleapis.com/auth/admin.reports.usage.readonly',
    ],
    message=MISSING_CLIENT_SECRETS_MESSAGE)

class MainHandler(webapp2.RequestHandler):

  @decorator.oauth_aware
  def get(self):
    devices = [ ]
    if (decorator.has_credentials()):
      credentials = decorator.get_credentials()
      auth_http = credentials.authorize(http)
      #reportsservice = discovery.build('admin', 'reports_v1', http=auth_http)
      directoryservice = discovery.build('admin', 'directory_v1', http=auth_http)
      #date_4daysago = (date.today() - timedelta(4)).isoformat()
      #custusage = reportsservice.customerUsageReports().get(date=date_4daysago).execute(http=auth_http)
      #customerid = custusage['usageReports'][0]['entity']['customerId']
      devicelistreq = directoryservice.chromeosdevices().list(customerId="my_customer", orderBy="lastSync", projection="FULL", sortOrder="DESCENDING")
      while True:
        devicelist = devicelistreq.execute(http=auth_http)
        for device in devicelist['chromeosdevices']:
          lastEnrollmentTime = datetime.strptime(device['lastEnrollmentTime'],'%Y-%m-%dT%H:%M:%S.%fZ') if 'lastEnrollmentTime' in device else None
          lastSync = datetime.strptime(device['lastSync'],'%Y-%m-%dT%H:%M:%S.%fZ') if 'lastSync' in device else None
          devices.append({
            'serialNumber': device['serialNumber'],
            'macAddress': ':'.join((device['macAddress'][i:i+2] if 'macAddress' in device else '??') for i in range(0,12,2)),
            'status': device['status'],
            'lastEnrollmentTime': 'Never' if lastEnrollmentTime is None else lastEnrollmentTime.strftime('%a, %d %b %Y, %H:%M UTC'),
            'lastSync': 'Never' if lastEnrollmentTime is None else lastSync.strftime('%a, %d %b %Y, %H:%M UTC'),
            'annotatedUser': device['annotatedUser'] if 'annotatedUser' in device else '',
	    'annotatedLocation': device['annotatedLocation'] if 'annotatedLocation' in device else '',
	    'notes': device['notes'] if 'notes' in device else '',
            'deviceId': device['deviceId']
            })
        if 'nextPageToken' in devicelist:
          devicelistreq = directoryservice.chromeosdevices().list_next(devicelistreq, devicelist)
        else:
          break
    variables = {
        'url': decorator.authorize_url(),
        'has_credentials': decorator.has_credentials(),
        'devices': devices,
        }
    template = JINJA_ENVIRONMENT.get_template('main.html')
    self.response.write(template.render(variables))


app = webapp2.WSGIApplication(
    [
     ('/', MainHandler),
     (decorator.callback_path, decorator.callback_handler()),
    ],
    debug=True)
