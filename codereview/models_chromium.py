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
  result = dict([(p, unicode(getattr(self, p))) for p in self.properties()])
  try:
    result['key'] = str(self.key())
  except db.NotSavedError:
    pass
  return result

# Monkey-patch db.Model to make it easier to JSON-serialize it.
db.Model.to_dict = to_dict
