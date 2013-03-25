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

  _DEFAULT_CHROMIUM_TRYSERVER_NAME = 'tryserver.chromium'

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
  def get_builders(cls, base_url):
    """Gets the list of default builders.

    This function will first attempt to get the list from the memcache. If its
    not available there, it will get it from the datastore and then update the
    memcache.

    Args:
      base_url: The base URL we want a list of default builders for.

    Returns:
      A list of strings where each string is the name of one builder. The
      names are sorted alphabetically.
    """
    # Remove contents after '@' to avoid explosion due to git branches.
    base_url = base_url.rsplit('@', 1)[0]
    # Look for the list of builders using the specified base url in memcache.
    base_url_key = cls._DEFAULT_BUILDER_MEMCACHE_KEY + base_url
    builders = memcache.get(base_url_key, namespace=base_url)
    if builders is None:
      # If the list of builders does not exist in memcache get it from the
      # datastore in 2 steps.
      # 1. Get the tryserver name from the datastore using the base_url.
      tryserver_name = BaseUrlTryServer.get_instance(
          base_url=base_url,
          tryserver_name=cls._DEFAULT_CHROMIUM_TRYSERVER_NAME).tryserver_name
      # 2. Get the list of builders from the datastore using the tryserver_name.
      builders = cls._get_instance(tryserver_name).default_builders
      # Set it in memcache to prevent future misses.
      memcache.set(base_url_key, builders,
                   time=cls._DEFAULT_BUILDER_MEMCACHE_EXPIRY_SECS,
                   namespace=base_url)
    return builders

  @classmethod
  def update(cls):
    """Updates all default builder lists for all build master servers.

    Returns:
      A tuple with two lists. The first list is a dict containing the names
      of build master servers successfully updated with values of changes.
      The second list contains the names of build master servers that failed
      to update.
    """
    successful = {}
    failed = []

    for obj in cls.all():
      tryserver_name = obj.key().name()
      try:
        successful[tryserver_name] = obj._update_builders(tryserver_name)
      except (ValueError, urlfetch.Error):
        logging.error(sys.exc_info()[1])
        failed.append(tryserver_name)

    return (successful, failed)

  def _update_builders(self, tryserver_name):
    """Updates the list of default builders by polling the master.

    This function makes a network request so should not be called while
    processing user requests.  This function also clears the memcache.

    Returns: dict of changes to trybot list.
    """
    json_urls = BaseUrlTryServer.get_json_urls(tryserver_name)
    if not json_urls:
      logging.error('json_urls not specified for %s' % tryserver_name)
      return {}

    old_builders = set(self.default_builders)
    builders = []
    for json_url in json_urls:
      result = urlfetch.fetch(json_url, deadline=60)
      # The returned data is a json encoded dictionary, where the keys are the
      # builder names and the values are information about the corresponding
      # builder.  We only need the names.
      # TODO(rogerta): may want to trim this list a bit, its pretty big.
      builders.extend(json.loads(result.content))
    builders.sort()
    # Exclude triggered bots: these cannot succeed with a associated build
    self.default_builders = [b for b in builders if not 'triggered' in b]
    memcache.set(self._DEFAULT_BUILDER_MEMCACHE_KEY + self.key().name(),
                 self.default_builders,
                 self._DEFAULT_BUILDER_MEMCACHE_EXPIRY_SECS)
    self.put()

    new_builders = set(self.default_builders)
    changes = [('added', list(new_builders - old_builders)),
               ('removed', list(old_builders - new_builders))]
    return dict((desc, items) for (desc, items) in changes if items)


class BaseUrlTryServer(db.Model):
  """Maps a Base URL to a TryServer name and JSON URL."""

  _DEFAULT_CHROMIUM_TRYSERVER_JSON_URLS = [
      'http://build.chromium.org/p/tryserver.chromium/json/builders',
      # Disabled? It is unavailable.
      # 'http://build.chromium.org/p/tryserver.chromium.linux/json/builders',
  ]

  tryserver_name = db.StringProperty(required=True)
  json_urls = db.StringListProperty()

  @classmethod
  def get_instance(cls, base_url, tryserver_name):
    """Gets the single instance of the base url try server.

    Args:
      base_url: The base URL we want try server information for.

    Returns:
      An instance of BaseUrlTryServer for the given base URL.
    """
    return cls.get_or_insert(base_url, tryserver_name=tryserver_name)

  @classmethod
  def get_json_urls(cls, tryserver_name):
    """Get the TryServer JSON URL(s) for a specified TryServer name."""
    baseurl_tryserver = cls.all().filter(
        'tryserver_name', tryserver_name).get()
    return (baseurl_tryserver.json_urls
            if baseurl_tryserver and baseurl_tryserver.json_urls
            else cls._DEFAULT_CHROMIUM_TRYSERVER_JSON_URLS)
