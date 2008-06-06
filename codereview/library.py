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

import django.template
import django.utils.safestring

import models

register = django.template.Library()


@register.filter
def nickname(email, arg=None):
  """Render an email address or a User object as a nickname.

  If the argument is a user object that equals the current user,
  'me' is returned, unless the argument is non-empty.
  """
  if isinstance(email, users.User):
    email = email.email()
  if not arg:
    user = users.get_current_user()
    if user is not None and email == user.email():
      return 'me'
  return models.Account.get_nickname_for_email(email)

@register.filter
def nicknames(email_list, arg=None):
  """Render a list of email addresses or User objects as nicknames.

  Each list item is first formatter via the nickname() filter above,
  and then the resulting strings are separated by commas.
  """
  return ', '.join(nickname(email, arg) for email in email_list)

@register.filter
def show_user(email, arg=None, autoescape=None):
  """Render a link to the user's dashboard, with text being the nickname."""
  # TODO(jiayao): Here seems to be a hotspot of queries, use memcache?
  nick = nickname(email, arg)
  if nick == 'me':
    return nick  
  account = models.Account.get_account_for_email(email)
  if account:
    if len(models.Account.get_accounts_for_nickname(account.nickname)) > 1:
      # nickname is not unique, fallback to email as key
      user_key = email
    else:
      user_key = nick
    return django.utils.safestring.mark_safe('<a href="/user/%s">%s</a>' % 
                                             (user_key, user_key))
  else:
    return nick

@register.filter
def show_users(email_list, arg=None):
  """Render list of links to each user's dashboard."""
  return django.utils.safestring.mark_safe(', '.join(show_user(email, arg)
                                                     for email in email_list))
