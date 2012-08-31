#!/usr/bin/env python
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

"""Test case runner."""

import os
import re
import sys
import unittest

TESTS_DIR = os.path.dirname(__file__)


def collect_test_modules():
  """Collects and yields test modules."""
  for fname in os.listdir(TESTS_DIR):
    if not re.match(r'test_.*\.py$', fname):
      continue
    try:
      yield __import__(fname[:-3])
    except ImportError, err:
      sys.stderr.write('Failed to import %s: %s\n' % (fname, err))
  raise StopIteration


def setup_test_env(sdk_path):
  """Sets up App Engine/Django test environment."""
  sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
  sys.path.insert(0, sdk_path)
  import dev_appserver
  dev_appserver.fix_sys_path()
  # google.appengine.ext.testbed.Testbed should set SERVER_SOFTWARE
  # and APPLICATION_ID environment variables, but we need them
  # earlier when Django import settings.py.
  os.environ['SERVER_SOFTWARE'] = 'DevTestrunner'  # used in settings.py
  os.environ['APPLICATION_ID'] = 'test-codereview'  # used in settings.py
  os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
  # Provide a dummy value for REQUEST_ID_HASH in environment. This is
  # needed for now to make appstats happy (see comments on
  # http://codereview.appspot.com/5305060/).
  os.environ['REQUEST_ID_HASH'] = 'testing'
  from google.appengine.dist import use_library
  use_library('django', '1.2')


def main():
  """Builds test suite from collected test modules and runs it."""
  suite = unittest.TestSuite()
  loader = unittest.TestLoader()
  for module in collect_test_modules():
    suite.addTests(loader.loadTestsFromModule(module))
  unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
  if len(sys.argv) != 2:
    sdk_path = os.path.join('..', 'google_appengine')
    if not os.path.exists(os.path.join(sdk_path, 'dev_appserver.py')):
      sys.stderr.write('usage: %s SDK_PATH\n' % sys.argv[0])
      sys.exit(1)
  else:
    sdk_path = sys.argv[1]
  setup_test_env(sdk_path)
  main()
