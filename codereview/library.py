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

from google.appengine.api import memcache
from google.appengine.api import users

import django.template
import django.utils.safestring
from django.core.urlresolvers import reverse

from codereview import models

register = django.template.Library()

user_cache = {}


def get_links_for_users(user_emails):
  """Return a dictionary of email->link to user page and fill caches."""
  link_dict = {}
  remaining_emails = set(user_emails)
  
  # initialize with email usernames
  for email in remaining_emails:
    nick = email.split('@', 1)[0]
    link_dict[email] = cgi.escape(nick)

  # look in the local cache
  for email in remaining_emails:
    if email in user_cache:
      link_dict[email] = user_cache[email]
  remaining_emails = remaining_emails - set(user_cache)

  if not remaining_emails:
    return link_dict

  # then look in memcache
  memcache_results = memcache.get_multi(remaining_emails,
                                        key_prefix="show_user:")
  for email in memcache_results:
    link_dict[email] = memcache_results[email]
    user_cache[email] = memcache_results[email]
  remaining_emails = remaining_emails - set(memcache_results)

  if not remaining_emails:
    return link_dict

  # and finally hit the datastore
  accounts = models.Account.get_accounts_for_emails(remaining_emails)
  for account in accounts:
    if account and account.user_has_selected_nickname:
      ret = ('<a href="%s" onMouseOver="M_showUserInfoPopup(this)">%s</a>' %
             (reverse('codereview.views.show_user', args=[account.nickname]),
              cgi.escape(account.nickname)))
      link_dict[account.email] = ret
    
  datastore_results = dict((e, link_dict[e]) for e in remaining_emails)
  memcache.set_multi(datastore_results, 300, key_prefix='show_user:')
  user_cache.update(datastore_results)

  return link_dict


def get_link_for_user(email):
  """Get a link to a user's profile page."""
  links = get_links_for_users([email])
  return links[email]


@register.filter
def show_user(email, arg=None, _autoescape=None, _memcache_results=None):
  """Render a link to the user's dashboard, with text being the nickname."""
  if isinstance(email, users.User):
    email = email.email()
  if not arg:
    user = users.get_current_user()
    if user is not None and email == user.email():
      return 'me'

  ret = get_link_for_user(email)

  return django.utils.safestring.mark_safe(ret)


@register.filter
def show_users(email_list, arg=None):
  """Render list of links to each user's dashboard."""
  new_email_list = []
  for email in email_list:
    if isinstance(email, users.User):
      email = email.email()
    new_email_list.append(email)

  links = get_links_for_users(new_email_list)

  if not arg:
    user = users.get_current_user()
    if user is not None:
      links[user.email()] = 'me'
      
  return django.utils.safestring.mark_safe(', '.join(
      links[email] for email in email_list))


class UrlAppendViewSettingsNode(django.template.Node):
  """Django template tag that appends context and column_width parameter.

  This tag should be used after any URL that requires view settings.

  Example:

    <a href='{%url /foo%}{%urlappend_view_settings%}'>

  The tag tries to get the current column width and context from the
  template context and if they're present it returns '?param1&param2'
  otherwise it returns an empty string.
  """

  def __init__(self):
    super(UrlAppendViewSettingsNode, self).__init__()
    self.view_context = django.template.Variable('context')
    self.view_colwidth = django.template.Variable('column_width')

  def render(self, context):
    """Returns a HTML fragment."""
    url_params = []

    current_context = -1
    try:
      current_context = self.view_context.resolve(context)
    except django.template.VariableDoesNotExist:
      pass
    if current_context is None:
      url_params.append('context=')
    elif isinstance(current_context, int) and current_context > 0:
      url_params.append('context=%d' % current_context)

    current_colwidth = None
    try:
      current_colwidth = self.view_colwidth.resolve(context)
    except django.template.VariableDoesNotExist:
      pass
    if current_colwidth is not None:
      url_params.append('column_width=%d' % current_colwidth)

    if url_params:
      return '?%s' % '&'.join(url_params)
    return ''

@register.tag
def urlappend_view_settings(_parser, _token):
  """The actual template tag."""
  return UrlAppendViewSettingsNode()


def get_nickname(email, never_me=False, request=None):
  """Return a nickname for an email address.

  If 'never_me' is True, 'me' is not returned if 'email' belongs to the
  current logged in user. If 'request' is a HttpRequest, it is used to
  cache the nickname returned by models.Account.get_nickname_for_email().
  """
  if isinstance(email, users.User):
    email = email.email()
  if not never_me:
    if request is not None:
      user = request.user
    else:
      user = users.get_current_user()
    if user is not None and email == user.email():
      return 'me'

  if request is None:
    return models.Account.get_nickname_for_email(email)

  # _nicknames is injected into request as a cache.
  # TODO(maruel): Use memcache instead.
  # Access to a protected member _nicknames of a client class
  # pylint: disable=W0212
  if getattr(request, '_nicknames', None) is None:
    request._nicknames = {}
  if email in request._nicknames:
    return request._nicknames[email]
  result = models.Account.get_nickname_for_email(email)
  request._nicknames[email] = result
  return result


class NicknameNode(django.template.Node):
  """Renders a nickname for a given email address.

  The return value is cached if a HttpRequest is available in a
  'request' template variable.

  The template tag accepts one or two arguments. The first argument is
  the template variable for the email address. If the optional second
  argument evaluates to True, 'me' as nickname is never rendered.

  Example usage:
    {% cached_nickname msg.sender %}
    {% cached_nickname msg.sender True %}
  """

  def __init__(self, email_address, never_me=''):
    """Constructor.

    'email_address' is the name of the template variable that holds an
    email address. If 'never_me' evaluates to True, 'me' won't be returned.
    """
    super(NicknameNode, self).__init__()
    self.email_address = django.template.Variable(email_address)
    self.never_me = bool(never_me.strip())
    self.is_multi = False

  def render(self, context):
    try:
      email = self.email_address.resolve(context)
    except django.template.VariableDoesNotExist:
      return ''
    request = context.get('request')
    if self.is_multi:
      return ', '.join(get_nickname(e, self.never_me, request) for e in email)
    return get_nickname(email, self.never_me, request)


@register.tag
def nickname(_parser, token):
  """Almost the same as nickname filter but the result is cached."""
  try:
    _, email_address, never_me = token.split_contents()
  except ValueError:
    try:
      _, email_address = token.split_contents()
      never_me = ''
    except ValueError:
      raise django.template.TemplateSyntaxError(
        "%r requires exactly one or two arguments" % token.contents.split()[0])
  return NicknameNode(email_address, never_me)


@register.tag
def nicknames(parser, token):
  """Wrapper for nickname tag with is_multi flag enabled."""
  node = nickname(parser, token)
  node.is_multi = True
  return node
