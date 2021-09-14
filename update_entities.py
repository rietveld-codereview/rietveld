# Re-puts entities of a given type, to set newly added properties.
#
# To run this script:
#  - Make sure App Engine library (incl. yaml) is in PYTHONPATH.
#  - Make sure that the remote API is included in app.yaml.
#  - Run "tools/appengine_console.py APP_ID".
#  - Import this module.
#  - Import models from codereview.
#  - update_entities.run(models.Issue) updates issues.


import logging
from google.appengine.api import datastore_errors
from google.appengine.ext import ndb
from codereview import models
import urllib2

def run(model_class, batch_size=100, last_key=None):
    while True:
      q = model_class.query()
      if last_key:
        q = q.filter(model_class.key > last_key)
      q = q.order(model_class.key)
      this_batch_size = batch_size

      while True:
        try:
          try:
            batch = q.fetch(this_batch_size)
          except urllib2.URLError, err:
            if 'timed out' in str(err):
              raise datastore_errors.Timeout
            else:
              raise
          break
        except datastore_errors.Timeout:
          logging.warn("Query timed out, retrying")
          if this_batch_size == 1:
            logging.critical("Unable to update entities, aborting")
            return
          this_batch_size //= 2

      if not batch:
        break

      keys = None
      while not keys:
        try:
          keys = ndb.put_multi(batch)
        except datastore_errors.Timeout:
          logging.warn("Put timed out, retrying")

      last_key = keys[-1]
      print "Updated %d records" % (len(keys),)
