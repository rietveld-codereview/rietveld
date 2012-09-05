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

"""App Engine data model (schema) definition for Chromium port of Rietveld."""

import json
import logging
import sys

from google.appengine.api import memcache
from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.ext import db


class UrlMap(db.Model):
  """Mapping between base url and source code viewer url."""

  base_url_template = db.StringProperty(required=True)
  source_code_url_template = db.StringProperty(required=True)


class Key(db.Model):
  """Hash to be able to push data from a server."""
  hash = db.StringProperty()


def to_dict(self):
  """Converts a db.Model instance into a dict.

  Useful for json serialization.
  """
  def convert(item):
    if isinstance(item, (int, float, None.__class__, bool)):
      return item
    elif isinstance(item, (list, tuple)):
      return [convert(i) for i in item]
    elif isinstance(item, users.User):
      return item.email()
    else:
      return unicode(item)
  result = dict([(p, convert(getattr(self, p))) for p in self.properties()])
  try:
    result['key'] = str(self.key())
  except db.NotSavedError:
    pass
  return result

# Monkey-patch db.Model to make it easier to JSON-serialize it.
db.Model.to_dict = to_dict


class DefaultBuilderList(db.Model):
  """An instance to hold the list of default builder names for trying patchsets.

  Each instance of this class holds the list of builder names for use with
  a given build master server.  Instances are updated periodically by
  a cron job (not very often since this list does not change quickly) and
  are used while processing the show() view.

  The key of the instance is the name of the build master server.

  Attributes:
    default_builders: List of strings, where each string is the name of one
        builder for the given try server.
  """
  # Constants for default builders memcache.
  _DEFAULT_BUILDER_MEMCACHE_KEY = 'default_builders_'
  _DEFAULT_BUILDER_MEMCACHE_EXPIRY_SECS = 60 * 60 * 12

  default_builders = db.StringListProperty(default=[])

  @classmethod
  def _get_instance(cls, name):
    """Gets the single instance of the default builder list.

    Args:
      name: The name of the build master, like 'tryserver.chromium'.

    Returns:
      An instance of DefaultBuilderList for the given build master.
    """
    return cls.get_or_insert(name, default_builders=[])

  @classmethod
  def get_builders(cls, name):
    """Gets the list of default builders.

    This function will first attempt to get the list from the memcache.  If
    its not available there, it will get it from the datastore and then update
    the memcache.

    Args:
      name: The name of the build master, like 'tryserver.chromium'.

    Returns:
      A list of strings where each string is the name of one builder.  The
      names are sorted alphabetically.
    """
    key = cls._DEFAULT_BUILDER_MEMCACHE_KEY + name
    builders = memcache.get(key)
    if builders is None:
      builders = cls._get_instance(name).default_builders
      memcache.set(key, builders, cls._DEFAULT_BUILDER_MEMCACHE_EXPIRY_SECS)
    return builders

  @classmethod
  def update(cls):
    """Updates all default builder lists for all build master servers.

    Returns:
      A tuple with two lists of strings.  The first list contains the names
      of build master servers successfully updated.  The second list contains
      the names of build master servers that failed to update.
    """
    successful = []
    failed = []

    for obj in cls.all():
      try:
        obj._update_builders()
        successful.append(obj.key().name())
      except (ValueError, urlfetch.Error):
        logging.error(sys.exc_info()[1])
        failed.append(obj.key().name())

    return (successful, failed)

  def _update_builders(self):
    """Updates the list of default builders by polling the master.

    This function makes a network request so should not be called while
    processing user requests.  This function also clears the memcache.
    """
    url = 'http://build.chromium.org/p/%s/json/builders' % self.key().name()
    result = urlfetch.fetch(url, deadline=60)
    # The returned data is a json encoded dictionary, where the keys are the
    # builder names and the values are information about the corresponding
    # builder.  We only need the names.
    # TODO(rogerta): may want to trim this list a bit, its pretty big.
    self.default_builders = sorted(json.loads(result.content))
    memcache.set(self._DEFAULT_BUILDER_MEMCACHE_KEY + self.key().name(),
                 self.default_builders,
                 self._DEFAULT_BUILDER_MEMCACHE_EXPIRY_SECS)
    self.put()
