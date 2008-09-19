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

import cgi
import logging

from google.appengine.api import memcache
from google.appengine.api import users

import django.template
import django.utils.safestring

import models

register = django.template.Library()


@register.filter
def nickname(email, arg=None):
  """Render an email address or a User object as a nickname.

  If the input is a user object that equals the current user,
  'me' is returned, unless the filter argument is non-empty.
  Example:
    {{foo|nickname}} may render 'me';
    {{foo|nickname:"x"}} will never render 'me'.
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
  The filter argument is the same as for nickname() above.
  """
  return ', '.join(nickname(email, arg) for email in email_list)


@register.filter
def show_user(email, arg=None, autoescape=None, memcache_results=None):
  """Render a link to the user's dashboard, with text being the nickname."""
  if isinstance(email, users.User):
    email = email.email()
  if not arg:
    user = users.get_current_user()
    if user is not None and email == user.email():
      return 'me'

  if memcache_results is not None:
    ret = memcache_results.get(email)
  else:
    ret = memcache.get('show_user:' + email)

  if ret is None:
    logging.debug('memcache miss for %r', email)
    account = models.Account.get_account_for_email(email)
    if account is not None and account.user_has_selected_nickname:
      ret = ('<a href="/user/%(key)s" onMouseOver="M_showUserInfoPopup(this)">'
             '%(key)s</a>' % {'key': cgi.escape(account.nickname)})
    else:
      # No account.  Let's not create a hyperlink.
      nick = email
      if '@' in nick:
        nick = nick.split('@', 1)[0]
      ret = cgi.escape(nick)

    memcache.add('show_user:%s' % email, ret, 300)

    # populate the dict with the results, so same user in the list later
    # will have a memcache "hit" on "read".
    if memcache_results is not None:
      memcache_results[email] = ret

  return django.utils.safestring.mark_safe(ret)


@register.filter
def show_users(email_list, arg=None):
  """Render list of links to each user's dashboard."""
  memcache_results = memcache.get_multi(email_list, key_prefix='show_user:')
  return django.utils.safestring.mark_safe(', '.join(
      show_user(email, arg, memcache_results=memcache_results)
      for email in email_list))
