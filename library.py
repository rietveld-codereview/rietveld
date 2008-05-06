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

"""Django template library for Rietveld."""

from google.appengine.api import users
from google.appengine.ext.webapp import template

import models

register = template.create_template_register()

@register.filter
def nickname(email, arg=None):
  """Render an email address or a User object as a nickname.

  If the argument is a user object that equals the current user,
  'me' is returned, unless the argument is non-empty.
  """
  if isinstance(email, users.User):
    if email == users.get_current_user() and not arg:
      return 'me'
    email = email.email()
  try:
    return models.Account.get_nickname_for_email(email)
  except:
    return email.replace('@', '_')

@register.filter
def nicknames(email_list, arg=None):
  """Render a list of email addresses or User objects as nicknames.

  Each list item is first formatter via the nickname() filter above,
  and then the resulting strings are separated by commas.
  """
  return ", ".join(nickname(email, arg) for email in email_list)
