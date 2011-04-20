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
import os
import re
import sys

ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..')
LIB = os.path.join(ROOT, '..', 'google_appengine', 'lib')
sys.path.append(os.path.join(ROOT, '..', 'google_appengine'))
sys.path.append(os.path.join(LIB, 'django_1_2'))
sys.path.append(os.path.join(LIB, 'fancy_urllib'))
sys.path.append(os.path.join(LIB, 'simplejson'))
sys.path.append(os.path.join(LIB, 'webob'))
sys.path.append(os.path.join(LIB, 'yaml', 'lib'))
sys.path.append(ROOT)

from google.appengine.ext.remote_api import remote_api_stub
import yaml


def auth_func():
  user = os.environ.get('EMAIL_ADDRESS')
  if user:
    print('User: %s' % user)
  else:
    user = raw_input('Username:')
  return user, getpass.getpass('Password:')


def main():
  if len(sys.argv) < 2:
    app_id = yaml.load(open(os.path.join(ROOT, 'app.yaml')))['application']
  else:
    app_id = sys.argv[1]
  if len(sys.argv) > 2:
    host = sys.argv[2]
  else:
    host = '%s.appspot.com' % app_id
  logging.basicConfig(level=logging.ERROR)

  # pylint: disable=W0612
  from google.appengine.api import memcache
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

  # Load all the models.
  for i in dir(models):
    if re.match(r'[A-Z][a-z]', i[:2]):
      predefined_vars[i] = getattr(models, i)

  prompt = (
      'App Engine interactive console for "%s".\n'
      'Available symbols:\n'
      '  %s\n') % (app_id, ', '.join(sorted(predefined_vars)))
  code.interact(prompt, None, predefined_vars)


if __name__ == '__main__':
  sys.exit(main())
