# Copyright 2011 Google Inc.
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

"""Test utils."""

import os

from google.appengine.ext import testbed

from django.test import TestCase as _TestCase


FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


class TestCase(_TestCase):
  """Customized Django TestCase.

  This class disables the setup of Django features that are not
  available on App Engine (e.g. fixture loading). And it initializes
  the Testbad class provided by the App Engine SDK.
  """

  def _fixture_setup(self):  # defined in django.test.TestCase
    pass

  def _fixture_teardown(self):  # defined in django.test.TestCase
    pass

  def setUp(self):
    super(TestCase, self).setUp()
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.init_datastore_v3_stub()
    self.testbed.init_user_stub()

  def tearDown(self):
    self.testbed.deactivate()
    super(TestCase, self).tearDown()

  def login(self, email):
    """Logs in a user identified by email."""
    os.environ['USER_EMAIL'] = email

  def logout(self):
    """Logs the user out."""
    os.environ['USER_EMAIL'] = ''


def load_file(fname):
  """Read file and return it's content."""
  return open(os.path.join(FILES_DIR, fname)).read()
