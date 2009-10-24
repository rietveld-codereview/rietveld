"""Configuration."""

import logging
logging.info('Loading %s from %s', __name__, __file__)

def webapp_add_wsgi_middleware(app):

  try:
    from appstats import recording
  except ImportError:
    logging.info('Failed to import recording: %s', err)
  else:
    app = recording.appstats_wsgi_middleware(app)

  try:
    from firepython import middleware
  except ImportError, err:
    logging.info('Failed to import firepython: %s', err)
  else:
    app = middleware.FirePythonWSGI(app)

  return app

import re

# Declare the Django version we need.
from google.appengine.dist import use_library
use_library('django', '1.0')
import django

# Custom appstats path normalization.
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
