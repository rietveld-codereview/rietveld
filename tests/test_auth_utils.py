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
from google.appengine.api.user_service_stub import _OAUTH_CLIENT_ID

from utils import TestCase

from codereview import auth_utils


TEST_EMAIL = 'foo@example.com'
EMAIL_SCOPE = auth_utils.EMAIL_SCOPE
CLIENT_ID = 'dummy21.apps.googleusercontent.com'
OTHER_CLIENT_IDS = [
  'dummy34.apps.googleusercontent.com',
  'dummy55.apps.googleusercontent.com',
  'dummy89.apps.googleusercontent.com',
]



class TestAuthUtils(TestCase):

  def setUp(self):
    super(TestAuthUtils, self).setUp()
    # User service stub used in TestAuthUtils, this protobuf service
    # includes the OAuth API.
    self.oauth_login(TEST_EMAIL)

    auth_utils.SecretKey.set_config(CLIENT_ID, 'dummy.secret',
                                    OTHER_CLIENT_IDS)

  def tearDown(self):
    super(TestAuthUtils, self).tearDown()
    self.oauth_logout()

  def cookie_login(self, email, is_admin=False):
    """Logs in Cookie user identified by email."""
    self.login(email)
    os.environ['USER_IS_ADMIN'] = '1' if is_admin else '0'

  def cookie_logout(self):
    """Logs the Cookie user out."""
    self.logout()
    os.environ['USER_IS_ADMIN'] = '0'

  def oauth_login(self, email, is_admin=False, client_id=CLIENT_ID):
    """Logs in OAuth user identified by email."""
    stub_map = self.testbed._test_stub_map._APIProxyStubMap__stub_map
    user_stub = stub_map['user']
    user_stub._UserServiceStub__email = email
    user_stub._UserServiceStub__is_admin = is_admin
    user_stub._client_id = client_id

  def oauth_logout(self):
    """Logs the OAuth user out."""
    stub_map = self.testbed._test_stub_map._APIProxyStubMap__stub_map
    user_stub = stub_map['user']
    user_stub._UserServiceStub__email = None
    user_stub._UserServiceStub__is_admin = False
    user_stub._client_id = _OAUTH_CLIENT_ID

  def test_oauth_works_as_expected_in_test(self):
    oauth_user = oauth.get_current_user(EMAIL_SCOPE)
    self.assertEqual(oauth_user.email(), TEST_EMAIL)
    self.assertEqual(oauth_user.auth_domain(), 'gmail.com')
    self.assertEqual(oauth_user.user_id(), '0')

    client_id = oauth.get_client_id(EMAIL_SCOPE)
    self.assertEqual(client_id, CLIENT_ID)

  def test_get_current_rietveld_oauth_user_success(self):
    oauth_user = auth_utils.get_current_rietveld_oauth_user()
    self.assertEqual(oauth_user.email(), TEST_EMAIL)
    self.assertEqual(oauth_user.auth_domain(), 'gmail.com')
    self.assertEqual(oauth_user.user_id(), '0')

  def test_get_current_rietveld_oauth_bad_client_id(self):
    self.oauth_login('any@mail.com', client_id='bad.id')
    self.assertIsNone(auth_utils.get_current_rietveld_oauth_user())

  def test_get_current_rietveld_oauth_other_client_id(self):
    any_mail = 'any@mail.com'
    for other_client_id in OTHER_CLIENT_IDS:
      self.oauth_login(any_mail, client_id=other_client_id)
      oauth_user = auth_utils.get_current_rietveld_oauth_user()
      self.assertEqual(oauth_user.email(), any_mail)
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

    current_user = auth_utils.get_current_user()
    self.assertEqual(current_user.email(), oauth_mail)

  def test_get_current_user_both_cookie_and_oauth_user(self):
    cookie_mail = 'cookie@mail.com'
    oauth_mail = 'oauth@mail.com'
    self.cookie_login(cookie_mail)
    self.oauth_login(oauth_mail)

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

    # Not an admin
    self.oauth_login(oauth_mail, is_admin=False)
    self.assertFalse(auth_utils.is_current_user_admin())

  def test_is_current_user_admin_oauth_only_is_admin(self):
    # Can't call is_current_user_admin twice in the same test because the OAuth
    # user gets set once and cached.
    oauth_mail = 'oauth@mail.com'

    # Is an admin
    self.oauth_login(oauth_mail, is_admin=True)
    self.assertTrue(auth_utils.is_current_user_admin())

  def test_is_current_user_admin_both_cookie_and_oauth_user(self):
    self.cookie_login('foo@bar.com', is_admin=True)
    self.oauth_login('oauth@mail.com', is_admin=True)

    self.assertTrue(auth_utils.is_current_user_admin())
