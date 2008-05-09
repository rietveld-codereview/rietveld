# Copyright 2008 Google Inc.
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

"""Main program for Rietveld.

This is also a template for running a Django app under Google App
Engine, especially when using a newer version of Django than provided
in the App Engine standard library.

The site-specific code is all in other files: urls.py, models.py,
views.py, settings.py.
"""

# Standard Python imports.
import os
import sys
import logging

# Log a message each time this module get loaded.
logging.info('Loading %s', __name__)

# Delete the preloaded copy of Django.
for key in [key for key in sys.modules if key.startswith('django')]:
  del sys.modules[key]

# Force sys.path to have our own directory first, so we can import from it.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# AppEngine imports.
from google.appengine.ext.webapp import util

# Helper to enter the debugger.  This passes in __stdin__ and
# __stdout__, because stdin and stdout are connected to the request
# and response streams.  You must import this from __main__ to use it.
# (I tried to make it universally available via __builtin__, but that
# doesn't seem to work for some reason.)
def BREAKPOINT():
  import pdb
  p = pdb.Pdb(None, sys.__stdin__, sys.__stdout__)
  p.set_trace()

# Custom Django configuration.
from django.conf import settings
settings._target = None
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

# Import various parts of Django.
import django.core.handlers.wsgi
import django.core.signals
import django.db
import django.dispatch.dispatcher

def log_exception(*args, **kwds):
  """Django signal handler to log an exception."""
  cls, err = sys.exc_info()[:2]
  logging.exception('Exception in request: %s: %s', cls.__name__, err)

# Log all exceptions detected by Django.
django.dispatch.dispatcher.connect(
    log_exception,
    django.core.signals.got_request_exception)

# Unregister Django's default rollback event handler.
django.dispatch.dispatcher.disconnect(
    django.db._rollback_on_exception,
    django.core.signals.got_request_exception)

def real_main():
  """Main program."""
  # Create a Django application for WSGI.
  application = django.core.handlers.wsgi.WSGIHandler()
  # Run the WSGI CGI handler with that application.
  util.run_wsgi_app(application)

def profile_main():
  """Main program for profiling."""
  import cProfile, pstats, StringIO
  prof = cProfile.Profile()
  prof = prof.runctx('real_main()', globals(), locals())
  stream = StringIO.StringIO()
  stats = pstats.Stats(prof, stream=stream)
  # stats.strip_dirs()  # Don't; too many modules are named __init__.py.
  stats.sort_stats('time')  # Or 'cumulative'
  stats.print_stats(80)  # 80 = how many to print
  # The rest is optional.
  # stats.print_callees()
  # stats.print_callers()
  logging.info('Profile data:\n%s', stream.getvalue())

# Set this to profile_main to enable profiling.
main = real_main

if __name__ == '__main__':
  main()
