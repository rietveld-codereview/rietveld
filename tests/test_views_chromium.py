#!/usr/bin/env python
# Copyright 2014 Google Inc.
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

"""Tests for chromium view functions and helpers."""

import datetime
import json
import unittest
import sha

import setup
setup.process_args()

from google.appengine.api import memcache, users
from google.appengine.ext import ndb



from utils import TestCase, load_file
from codereview import models
from codereview import engine  # engine must be imported after models :(


class TestStatusListener(TestCase):

  def setUp(self):
      super(TestStatusListener, self).setUp()
      self.user = users.User('foo@example.com')
      self.login('foo@example.com')
      self.issue = models.Issue(subject='test')
      self.issue.local_base = False
      self.issue.put()
      self.ps = models.PatchSet(parent=self.issue.key, issue_key=self.issue.key)
      self.ps.data = load_file('ps1.diff')
      self.ps.put()
      self.patches = engine.ParsePatchSet(self.ps)
      ndb.put_multi(self.patches)
      self.logout() # Need to log out for /status_listener to work

  def test_status_listener(self):
    fake_packet = {
      'project': 'chromium',
      'timestamp': '2014-08-01 12:00:00.1',
      'event': 'buildFinished',
      'payload': {
        'build': {
          'results': [models.TryJobResult.FAILURE],
          'properties': [
            ('buildername', 'builder', ''),
            ('buildnumber', 1, ''),
            ('slavename', 'slave', ''),
            ('revision', 1, ''),
            ('issue', self.issue.key.id(), ''),
            ('patchset', self.ps.key.id(), ''),
          ],
        }
      }
    }

    password = 'password'
    password_hash = sha.new(password).hexdigest()
    memcache.add('key_required', password_hash, 60)

    response = self.client.post('/status_listener', {
      'password': password,
      'packets': json.dumps([
        fake_packet
      ]),
      'base_url': 'foo.com',
    })
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')

    try_job_result = models.TryJobResult.query().get()
    self.assertEquals(try_job_result.result, models.TryJobResult.FAILURE)


if __name__ == '__main__':
  unittest.main()
