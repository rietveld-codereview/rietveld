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

from . import library
from . import models
from .common import IS_DEV

from google.appengine.api import users

from django.conf import settings as django_settings
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext


# Counter displayed (by respond()) below) on every page showing how
# many requests the current incarnation has handled, not counting
# redirects.  Rendered by templates/base.html.
COUNTER = 0


class HttpTextResponse(HttpResponse):
  def __init__(self, *args, **kwargs):
    kwargs['content_type'] = 'text/plain; charset=utf-8'
    super(HttpTextResponse, self).__init__(*args, **kwargs)


class HttpHtmlResponse(HttpResponse):
  def __init__(self, *args, **kwargs):
    kwargs['content_type'] = 'text/html; charset=utf-8'
    super(HttpHtmlResponse, self).__init__(*args, **kwargs)


def respond(request, template, params=None):
  """Helper to render a response, passing standard stuff to the response.

  Args:
    request: The request object.
    template: The template name; '.html' is appended automatically.
    params: A dict giving the template parameters; modified in-place.

  Returns:
    Whatever render_to_response(template, params) returns.

  Raises:
    Whatever render_to_response(template, params) raises.
  """
  global COUNTER
  COUNTER += 1
  if params is None:
    params = {}
  must_choose_nickname = False
  if request.user is not None:
    account = models.Account.current_user_account
    must_choose_nickname = not account.user_has_selected_nickname()
  params['request'] = request
  params['counter'] = COUNTER
  params['user'] = request.user
  params['is_admin'] = request.user_is_admin
  params['is_dev'] = IS_DEV
  params['media_url'] = django_settings.MEDIA_URL
  params['special_banner'] = getattr(django_settings, 'SPECIAL_BANNER', None)
  full_path = request.get_full_path().encode('utf-8')
  if request.user is None:
    params['sign_in'] = users.create_login_url(full_path)
  else:
    params['sign_out'] = users.create_logout_url(full_path)
    account = models.Account.current_user_account
    if account is not None:
      params['xsrf_token'] = account.get_xsrf_token()
  params['must_choose_nickname'] = must_choose_nickname
  params['rietveld_revision'] = django_settings.RIETVELD_REVISION
  try:
    return render_to_response(template, params,
                              context_instance=RequestContext(request))
  finally:
    library.user_cache.clear() # don't want this sticking around
