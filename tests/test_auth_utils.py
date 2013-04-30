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

import json
import os
import urllib

from google.appengine.api import oauth
from google.appengine.api import users
from google.appengine.api.user_service_stub import _OAUTH_EMAIL as OAUTH_EMAIL
from google.appengine.api import urlfetch

from utils import TestCase

from codereview import auth_utils


TOKENINFO_URL_WITH_QUERY = auth_utils.TOKENINFO_URL + '?access_token='
DEFAULT_STATUS_CODE = 200
TEST_EMAIL = 'foo@example.com'
EMAIL_SCOPE = auth_utils.EMAIL_SCOPE
CLIENT_ID = 'dummy29.apps.googleusercontent.com'


class DummyURLFetchResponse(object):
  def __init__(self, content, status_code=DEFAULT_STATUS_CODE):
    self.content = content
    self.status_code = status_code


class TestAuthUtils(TestCase):

  def setUp(self):
    super(TestAuthUtils, self).setUp()
    self.testbed.init_urlfetch_stub()
    # User service stub used in TestAuthUtils, this protobuf service
    # includes the OAuth API.
    self.oauth_login(TEST_EMAIL)
    self.auth_header = None
    if 'HTTP_AUTHORIZATION' in os.environ:
      self.auth_header = os.environ['HTTP_AUTHORIZATION']
      del os.environ['HTTP_AUTHORIZATION']
    self.original_fetch = urlfetch.fetch

    auth_utils.SecretKey.set_config(CLIENT_ID, 'dummy.secret')

  def tearDown(self):
    super(TestAuthUtils, self).tearDown()
    self.oauth_logout()
    if self.auth_header is not None:
      os.environ['HTTP_AUTHORIZATION'] = self.auth_header
    urlfetch.fetch = self.original_fetch

  def cookie_login(self, email, is_admin=False):
    """Logs in Cookie user identified by email."""
    self.login(email)
    os.environ['USER_IS_ADMIN'] = '1' if is_admin else '0'

  def cookie_logout(self):
    """Logs the Cookie user out."""
    self.logout()
    os.environ['USER_IS_ADMIN'] = '0'

  def oauth_login(self, email, is_admin=False):
    """Logs in OAuth user identified by email."""
    stub_map = self.testbed._test_stub_map._APIProxyStubMap__stub_map
    user_stub = stub_map['user']
    user_stub._UserServiceStub__email = email
    user_stub._UserServiceStub__is_admin = is_admin

  def oauth_logout(self):
    """Logs the OAuth user out."""
    stub_map = self.testbed._test_stub_map._APIProxyStubMap__stub_map
    user_stub = stub_map['user']
    user_stub._UserServiceStub__email = None
    user_stub._UserServiceStub__is_admin = False

  def make_tokeninfo_fetch(self, response, status_code=DEFAULT_STATUS_CODE):
    """Creates a dummy replacement for urlfetch.fetch.

    This is intended to be used only for token info fetches and fails
    if the URL is not a token info URL or if any arguments other than
    the URL are passed in.

    Args:
      response: The response to be returned when this method is called.
      status_code: The status code of the response.

    Returns:
      Dummy method for fetching token info.
    """
    def dummy_fetch(url, *args, **kwargs):
      # Only allow the signature used in auth utils
      if not url.startswith(TOKENINFO_URL_WITH_QUERY):
        self.fail('Token info fetcher called with non-tokeninfo '
                  'URL: %r.' % (url,))
      if args or kwargs:
        self.fail('Only the URL can be specified in token info fetcher.')
      return DummyURLFetchResponse(response, status_code=status_code)
    return dummy_fetch

  def test_oauth_works_as_expected_in_test(self):
    oauth_user = oauth.get_current_user(EMAIL_SCOPE)
    self.assertEqual(oauth_user.email(), TEST_EMAIL)
    self.assertEqual(oauth_user.auth_domain(), 'gmail.com')
    self.assertEqual(oauth_user.user_id(), '0')

  def test_get_oauth_token_from_env_no_header(self):
    # Set-up guarentees the header won't be set
    self.assertIsNone(auth_utils.get_oauth_token_from_env())

  def test_get_oauth_token_from_env_bad_header(self):
    os.environ['HTTP_AUTHORIZATION'] = 'Not close'
    self.assertIsNone(auth_utils.get_oauth_token_from_env())
    os.environ['HTTP_AUTHORIZATION'] = 'OAuthSoCloseButNoSpace'
    self.assertIsNone(auth_utils.get_oauth_token_from_env())

  def test_get_oauth_token_from_env_success(self):
    token = 'abc'

    os.environ['HTTP_AUTHORIZATION'] = 'OAuth ' + token
    self.assertEqual(auth_utils.get_oauth_token_from_env(), token)

    os.environ['HTTP_AUTHORIZATION'] = 'Bearer ' + token
    self.assertEqual(auth_utils.get_oauth_token_from_env(), token)

    os.environ['HTTP_AUTHORIZATION'] = 'oaUTh ' + token  # Case doesn't matter
    self.assertEqual(auth_utils.get_oauth_token_from_env(), token)

  def test_get_token_info_bad_status(self):
    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch('Response is Moot',
                                               status_code=400)
    self.assertIsNone(auth_utils.get_token_info('abc'))

    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch('Response is Moot',
                                               status_code=503)
    self.assertIsNone(auth_utils.get_token_info('abc'))

  def test_get_token_info_bad_content(self):
    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch(None)  # Wrong type
    self.assertIsNone(auth_utils.get_token_info('abc'))

    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch('{')  # Invalid JSON
    self.assertIsNone(auth_utils.get_token_info('abc'))

    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch('[]')  # Invalid return type
    self.assertIsNone(auth_utils.get_token_info('abc'))

  def test_get_token_info_success(self):
    token_info = {'email': TEST_EMAIL}
    token_info_json = json.dumps(token_info)

    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch(token_info_json)
    self.assertEqual(auth_utils.get_token_info('abc'), token_info)

  def test_check_token_info_invalid_email(self):
    # Auth domain should be set by users stub, which is registered in TestCase
    oauth_user = users.User(TEST_EMAIL)
    token_info = {}

    # No email
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))

    # Email not verified
    token_info['email'] = TEST_EMAIL
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))
    token_info['verified_email'] = False
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))

    token_info['verified_email'] = True

    # Email disagrees with OAuth user
    token_info['email'] = 'foo'
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))
    token_info['email'] = TEST_EMAIL

    # No scope at all
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))
    # Scope not equal to email
    token_info['scope'] = 'fake scope right here'
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))

  def test_check_token_info_invalid_audience(self):
    # Auth domain should be set by users stub, which is registered in TestCase
    oauth_user = users.User(TEST_EMAIL)
    token_info = {
      'email': TEST_EMAIL,
      'verified_email': True,
      'scope': EMAIL_SCOPE
    }

    # No audience
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))

    wrong_client_id = 'foo'
    token_info['audience'] = wrong_client_id

    # No issued to
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))
    # Issued to differs from audience
    token_info['issued_to'] = 'bar'
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))

    # Issued to and audience agree, audience not equal to CLIENT_ID
    token_info['issued_to'] = wrong_client_id
    self.assertFalse(auth_utils.check_token_info(token_info, oauth_user))

  def test_check_token_info_success(self):
    # Auth domain should be set by users stub, which is registered in TestCase
    oauth_user = users.User(TEST_EMAIL)
    token_info = {
      'email': TEST_EMAIL,
      'verified_email': True,
      'scope': EMAIL_SCOPE,
      'audience': CLIENT_ID,
      'issued_to': CLIENT_ID,
    }
    self.assertTrue(auth_utils.check_token_info(token_info, oauth_user))

  def test_get_current_rietveld_oauth_user_bad_token(self):
    os.environ['HTTP_AUTHORIZATION'] = 'Not close'
    self.assertIsNone(auth_utils.get_current_rietveld_oauth_user())
    os.environ['HTTP_AUTHORIZATION'] = 'OAuthSoCloseButNoSpace'
    self.assertIsNone(auth_utils.get_current_rietveld_oauth_user())

  def test_get_current_rietveld_oauth_user_bad_token_info(self):
    os.environ['HTTP_AUTHORIZATION'] = 'Bearer Grylls'
    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch('Response is Moot',
                                               status_code=400)
    self.assertIsNone(auth_utils.get_current_rietveld_oauth_user())

    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch('{')  # Invalid JSON
    self.assertIsNone(auth_utils.get_current_rietveld_oauth_user())

    # tearDown will set urlfetch.fetch back to the original for us
    token_info_no_audience = {
      'email': TEST_EMAIL,
      'verified_email': True,
      'scope': EMAIL_SCOPE,
    }
    urlfetch.fetch = self.make_tokeninfo_fetch(
        json.dumps(token_info_no_audience))
    self.assertIsNone(auth_utils.get_current_rietveld_oauth_user())

  def set_rietveld_user_success_vars(self, email=TEST_EMAIL):
    os.environ['HTTP_AUTHORIZATION'] = 'Bearer Grylls'
    token_info = json.dumps({
      'email': email,
      'verified_email': True,
      'scope': EMAIL_SCOPE,
      'audience': CLIENT_ID,
      'issued_to': CLIENT_ID,
    })
    # tearDown will set urlfetch.fetch back to the original for us
    urlfetch.fetch = self.make_tokeninfo_fetch(token_info)

  def test_get_current_rietveld_oauth_user_success(self):
    self.set_rietveld_user_success_vars()
    oauth_user = auth_utils.get_current_rietveld_oauth_user()
    self.assertEqual(oauth_user.email(), TEST_EMAIL)
    self.assertEqual(oauth_user.auth_domain(), 'gmail.com')
    self.assertEqual(oauth_user.user_id(), '0')

  def test_get_current_user_no_users(self):
    self.cookie_logout()
    self.oauth_logout()
    self.assertIsNone(auth_utils.get_current_user())

  def test_get_current_user_only_cookie_user(self):
    dummy_mail = 'foo@bar.com'
    self.cookie_login(dummy_mail)
    self.oauth_logout()
    current_user = auth_utils.get_current_user()
    self.assertEqual(current_user.email(), dummy_mail)
    self.cookie_logout()

  def test_get_current_user_success(self):
    oauth_mail = 'oauth@mail.com'
    self.oauth_login(oauth_mail)
    self.set_rietveld_user_success_vars(email=oauth_mail)

    current_user = auth_utils.get_current_user()
    self.assertEqual(current_user.email(), oauth_mail)

  def test_get_current_user_both_cookie_and_oauth_user(self):
    cookie_mail = 'cookie@mail.com'
    oauth_mail = 'oauth@mail.com'
    self.cookie_login(cookie_mail)
    self.oauth_login(oauth_mail)
    self.set_rietveld_user_success_vars(email=oauth_mail)

    # Make sure the OAuth API still works
    oauth_user = oauth.get_current_user(EMAIL_SCOPE)
    self.assertEqual(oauth_user.email(), oauth_mail)

    # Make sure current user is the Cookie user in the case both are set
    current_user = auth_utils.get_current_user()
    self.assertEqual(current_user.email(), cookie_mail)
    self.cookie_logout()

  def test_is_current_user_admin_no_users(self):
    self.cookie_logout()
    self.oauth_logout()
    self.assertFalse(auth_utils.is_current_user_admin())

  def test_is_current_user_admin_only_cookie_user(self):
    # Cookie only
    self.oauth_logout()

    dummy_mail = 'foo@bar.com'

    # Not an admin
    self.cookie_login(dummy_mail, is_admin=False)
    self.assertFalse(auth_utils.is_current_user_admin())

    # Is an admin
    self.cookie_login(dummy_mail, is_admin=True)
    self.assertTrue(auth_utils.is_current_user_admin())

    self.cookie_logout()

  def test_is_current_user_admin_oauth_only_not_admin(self):
    # Can't call is_current_user_admin twice in the same test because the OAuth
    # user gets set once and cached.
    oauth_mail = 'oauth@mail.com'
    self.set_rietveld_user_success_vars(email=oauth_mail)

    # Not an admin
    self.oauth_login(oauth_mail, is_admin=False)
    self.assertFalse(auth_utils.is_current_user_admin())

  def test_is_current_user_admin_oauth_only_is_admin(self):
    # Can't call is_current_user_admin twice in the same test because the OAuth
    # user gets set once and cached.
    oauth_mail = 'oauth@mail.com'
    self.set_rietveld_user_success_vars(email=oauth_mail)

    # Is an admin
    self.oauth_login(oauth_mail, is_admin=True)
    self.assertTrue(auth_utils.is_current_user_admin())

  def test_is_current_user_admin_both_cookie_and_oauth_user(self):
    self.cookie_login('foo@bar.com', is_admin=True)
    self.oauth_login('oauth@mail.com', is_admin=True)

    self.assertTrue(auth_utils.is_current_user_admin())
