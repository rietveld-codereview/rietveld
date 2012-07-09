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

# Custom Appstats path normalization.
def appstats_normalize_path(path):
    if path.startswith('/user/'):
        return '/user/X'
    if path.startswith('/user_popup/'):
        return '/user_popup/X'
    if '/diff/' in path:
      return '/X/diff/...'
    if '/diff2/' in path:
      return '/X/diff2/...'
    if '/patch/' in path:
      return '/X/patch/...'
    if path.startswith('/rss/'):
        i = path.find('/', 5)
        if i > 0:
            return path[:i] + '/X'
    return re.sub(r'\d+', 'X', path)

# Segregate Appstats by runtime (python vs. python27).
appstats_KEY_NAMESPACE = '__appstats_%s__' % os.getenv('APPENGINE_RUNTIME')

# Django 1.2+ requires DJANGO_SETTINGS_MODULE environment variable to be set
# http://code.google.com/appengine/docs/python/tools/libraries.html#Django 
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
# NOTE: All "main" scripts must import webapp.template before django.

