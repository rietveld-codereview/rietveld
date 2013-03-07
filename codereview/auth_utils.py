# Copyright 2013 Google Inc.
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

"""Collection of functions to be used for Auth related activies.

The two methods to be chiefy used are:
  - get_current_user
  - is_current_user_admin

Both of these methods check for a cookie-based current user (through the Users
API) and an OAuth 2.0 current user (through the OAuth API).

In the OAuth 2.0 case, we also check that the token from the request was minted
for this specific application. This is because we have no scope of our own to
check, so must use the client ID for the token as a proxy for scope.

We use Google's email scope when using oauth.get_current_user and
oauth.is_current_user_admin, since these methods require this scope *as a
minimum* to return a users.User object (since User objects have an email
attribute). As an extra check, we also make sure that OAuth 2.0 tokens used have
been minted with *only* the email scope.

See google.appengine.ext.endpoints.users_id_token for reference:
('https://code.google.com/p/googleappengine/source/browse/trunk/python/google/'
 'appengine/ext/endpoints/users_id_token.py')
"""

import json
import logging
import os
import urllib

from google.appengine.api import oauth
from google.appengine.api import urlfetch
from google.appengine.api import users

from django.conf import settings


EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'
TOKENINFO_URL = 'https://www.googleapis.com/oauth2/v1/tokeninfo'
_ALLOWED_AUTH_SCHEMES = ('OAUTH ', 'BEARER ')

IS_DEV = os.environ['SERVER_SOFTWARE'].startswith('Dev')  # Development server


def get_oauth_token_from_env():
  """Gets an OAuth 2.0 token string from an HTTP header set in the environment.

  Returns:
    String containing the HTTP Authorization header, if HTTP_AUTHORIZATION is
        found in the OS environment and if the value begins one of the accept
        scheme values. Otherwise returns None.
  """
  auth_header = os.getenv('HTTP_AUTHORIZATION')
  if auth_header is None:
    logging.debug('No authorization header sent with request.')
    return

  for auth_scheme in _ALLOWED_AUTH_SCHEMES:
    if auth_header.upper().startswith(auth_scheme):
      return auth_header[len(auth_scheme):]

  logging.warning('Auth header %r does not begin with any of the allowed '
                  'schemes: %r', auth_header, _ALLOWED_AUTH_SCHEMES)


def get_token_info(token):
  """Gets OAuth 2.0 token info from Google's token info API.

  Args:
    token: String containing on OAuth 2.0 token.

  Returns:
    Dictionary parsed from the JSON in the token info API response. If the
        response is not a 200, the response body can't be decoded as JSON or
        it isn't decoded as a dictionary, returns None.
  """
  logging.debug('Getting token info for OAuth token: %r:', token)

  tokeninfo_result = urlfetch.fetch(
      '%s?%s' % (TOKENINFO_URL, urllib.urlencode({'access_token': token})))
  if tokeninfo_result.status_code != 200:
    logging.warning('Tokeninfo could not be retrieved. Token info API returned '
                    'status code %d.', tokeninfo_result.status_code)
    return

  try:
    token_info = json.loads(tokeninfo_result.content)
    if not isinstance(token_info, dict):
      raise ValueError('Parsed token info not a dictionary.')
    return token_info
  except (ValueError, TypeError):
    logging.warning('Token info JSON couldn\'t be parsed.')


def check_token_info(token_info, oauth_user):
  """Checks that token info agrees with user from OAuth library.

  For the token info to be valid for this application, all the following
  must hold:
    - The token info must contain a *verified* email which is equal to the
      email on the oauth_user object.
    - The token info must have scope equal to Google's email scope, meaning
      this scope can only be used to obtain the user's email.
    - The token info must contain identical audience and issued to values. If
      they differ, this indicated the token was not minted from a command line
      tool.
    - The audience (and issued to) value must be equal to the client ID
      associated with this application.

  Args:
    token_info: Dictionary containing token information retrieved from Google's
        token info API.
    oauth_user: users.User object that was retrieved from the App Engine OAuth
        library.

  Returns:
    Boolean indicating whether or not token info is valid for this application
        and agrees with the OAuth user.
  """
  # Email checks
  email = token_info.get('email')
  if email is None:
    logging.warning('Token info doesn\'t include an email address.')
    return False

  if not token_info.get('verified_email'):
    logging.warning('Token info email %r isn\'t verified.', email)
    return False

  if email != oauth_user.email():
    logging.warning('Token info email %r disagrees with value returned by '
                    'OAuth library: %r.', email, oauth_user.email())
    return False

  # Scope check
  if token_info.get('scope') != EMAIL_SCOPE:
    logging.warning('Scope %r differs from email scope.',
                    token_info.get('scope'))
    return False

  # Audience checks
  audience = token_info.get('audience')

  if audience is None:
    logging.warning('Audience is required and isn\'t specified in token info.')
    return False

  if audience != token_info.get('issued_to'):
    logging.warning('Command line tokens must have the same issued to and '
                    'audience. Audience %r is different from issued to %r.',
                    audience, token_info.get('issued_to'))
    return False

  if audience != settings.RIETVELD_CLIENT_ID:
    logging.warning('Audience %r not intended for this application.', audience)
    return False

  return True


def get_current_rietveld_oauth_user():
  """Gets the current OAuth 2.0 user associated with a request.

  This user must be intending to reach this application, so we check the token
  info to verify this is the case.

  Returns:
    A users.User object that was retrieved from the App Engine OAuth library if
        the token is valid, otherwise None.
  """
  # TODO(dhermes): Address local environ here as well.
  try:
    current_oauth_user = oauth.get_current_user(EMAIL_SCOPE)
  except oauth.Error:
    logging.debug('No OAuth user was found.')
    return

  token = get_oauth_token_from_env()
  if token is None:
    return

  token_info = get_token_info(token)
  if token_info is None:
    return

  if check_token_info(token_info, current_oauth_user):
    return current_oauth_user


def get_current_user():
  """Gets the current user associated with a request.

  First tries to verify a user with the Users API (cookie-based auth), and then
  falls back to checking for an OAuth 2.0 user with a token minted for use with
  this application.

  Returns:
    A users.User object that was retrieved from the App Engine Users or OAuth
        library if such a user can be determined, otherwise None.
  """
  current_cookie_user = users.get_current_user()
  if current_cookie_user is not None:
    return current_cookie_user

  logging.debug('No user found from session cookies.')

  return get_current_rietveld_oauth_user()


def is_current_user_admin():
  """Determines if the current user associated with a request is an admin.

  First tries to verify if the user is an admin with the Users API (cookie-based
  auth), and then falls back to checking for an OAuth 2.0 admin user with a
  token minted for use with this application.

  Returns:
    Boolean indicating whether or not the current user is an admin.
  """
  cookie_user_is_admin = users.is_current_user_admin()
  if cookie_user_is_admin:
    return cookie_user_is_admin

  # oauth.is_current_user_admin is not sufficient, we must first check that the
  # OAuth 2.0 user has a token minted for this application.
  rietveld_user = get_current_rietveld_oauth_user()
  if rietveld_user is None:
    return False

  return oauth.is_current_user_admin(EMAIL_SCOPE)
