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

"""Collection of helper functions."""

from google.appengine.ext import db


def to_dbtext(text):
  """Helper to turn a string into a db.Text instance.

  Args:
    text: a string.

  Returns:
    A db.Text instance.
  """
  if isinstance(text, unicode):
    # A TypeError is raised if text is unicode and an encoding is given.
    return db.Text(text)
  else:
    try:
      return db.Text(text, encoding='utf-8')
    except UnicodeDecodeError:
      return db.Text(text, encoding='latin-1')


def unify_linebreaks(text):
  """Helper to return a string with all line breaks converted to LF.

  Args:
    text: a string.

  Returns:
    A string with all line breaks converted to LF.
  """
  return text.replace('\r\n', '\n').replace('\r', '\n')

