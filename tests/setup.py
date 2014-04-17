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

"""Setup the test environment."""

import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def setup_test_env(sdk_path):
  """Sets up App Engine/Django test environment."""
  sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
  sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../third_party'))
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


def process_args():
  """Scans for a path to dev_appserver in sys.argv and pops it."""
  sdk_path = os.path.join(TESTS_DIR, '..', '..', 'google_appengine')
  for i in range(1, len(sys.argv)):
    if os.path.exists(os.path.join(sys.argv[i], 'dev_appserver.py')):
      sdk_path = sys.argv.pop(i)
      break
  if not os.path.exists(os.path.join(sdk_path, 'dev_appserver.py')):
    sys.stderr.write('usage: %s SDK_PATH\n' % sys.argv[0])
    sys.exit(1)
  setup_test_env(sdk_path)
