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

import code
import getpass
import logging
import optparse
import os
import re
import sys

ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..')
LIB = os.path.join(ROOT, '..', 'google_appengine', 'lib')
sys.path.insert(0, os.path.join(ROOT, '..', 'google_appengine'))
sys.path.append(os.path.join(LIB, 'django_1_2'))
sys.path.append(os.path.join(LIB, 'fancy_urllib'))
sys.path.append(os.path.join(LIB, 'simplejson'))
sys.path.append(os.path.join(LIB, 'webob'))
sys.path.append(os.path.join(LIB, 'yaml', 'lib'))
sys.path.append(ROOT)

from google.appengine.ext.remote_api import remote_api_stub
import yaml


def default_auth_func():
  user = os.environ.get('EMAIL_ADDRESS')
  if user:
    print('User: %s' % user)
  else:
    user = raw_input('Username:')
  return user, getpass.getpass('Password:')


def smart_auth_func():
  """Try to guess first."""
  try:
    return os.environ['EMAIL_ADDRESS'], open('.pwd').readline().strip()
  except (KeyError, IOError):
    return default_auth_func()


def default_app_id(directory):
  return yaml.load(open(os.path.join(directory, 'app.yaml')))['application']


def setup_env(app_id, host=None, auth_func=None):
  """Setup remote access to a GAE instance."""
  auth_func = auth_func or smart_auth_func
  host = host or '%s.appspot.com' % app_id

  # pylint: disable=W0612
  from google.appengine.api import memcache
  from google.appengine.api.users import User
  from google.appengine.ext import db
  remote_api_stub.ConfigureRemoteDatastore(
      app_id, '/_ah/remote_api', auth_func, host)

  # Initialize environment.
  os.environ['SERVER_SOFTWARE'] = ''
  import appengine_config

  # Create shortcuts.
  import codereview
  from codereview import models, views

  # Symbols presented to the user.
  predefined_vars = locals().copy()
  del predefined_vars['appengine_config']
  del predefined_vars['auth_func']

  # Load all the models.
  for i in dir(models):
    if re.match(r'[A-Z][a-z]', i[:2]):
      predefined_vars[i] = getattr(models, i)
  return predefined_vars


def main():
  parser = optparse.OptionParser()
  parser.add_option('-v', '--verbose', action='count')
  options, args = parser.parse_args()

  if not args:
    app_id = default_app_id(ROOT)
  else:
    app_id = args[0]

  host = None
  if len(args) > 1:
    host = args[1]

  if options.verbose:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.ERROR)

  predefined_vars = setup_env(app_id, host)
  prompt = (
      'App Engine interactive console for "%s".\n'
      'Available symbols:\n'
      '  %s\n') % (app_id, ', '.join(sorted(predefined_vars)))
  code.interact(prompt, None, predefined_vars)


if __name__ == '__main__':
  sys.exit(main())
