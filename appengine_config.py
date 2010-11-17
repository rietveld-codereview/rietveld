"""Configuration."""

import logging
import os
import re

from google.appengine.ext.appstats import recording

logging.info('Loading %s from %s', __name__, __file__)

# Custom webapp middleware to add Appstats.
def webapp_add_wsgi_middleware(app):
  app = recording.appstats_wsgi_middleware(app)
  return app

# Appstats URL.
# TODO: Drop this once it is the default.
appstats_stats_url = '/_ah/stats'

# Custom Appstats path normalization.
def appstats_normalize_path(path):
    if path.startswith('/user/'):
        return '/user/X'
    if path.startswith('/user_popup/'):
        return '/user_popup/X'
    if path.startswith('/rss/'):
        i = path.find('/', 5)
        if i > 0:
            return path[:i] + '/X'
    return re.sub(r'\d+', 'X', path)

# Declare the Django version we need.
from google.appengine.dist import use_library
use_library('django', '1.0')

# Fail early if we can't import Django 1.x.  Log identifying information.
import django
logging.info('django.__file__ = %r, django.VERSION = %r',
             django.__file__, django.VERSION)
assert django.VERSION[0] >= 1, "This Django version is too old"

# Custom Django configuration.
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
from django.conf import settings
settings._target = None
