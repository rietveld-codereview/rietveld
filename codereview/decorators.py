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

import collections
import functools
import logging
import mimetypes
import urllib
import json

from . import models
from .responses import HttpTextResponse, respond

from google.appengine.api import users

from django.conf import settings as django_settings
from django.http import HttpResponse, HttpResponseRedirect


# Singleton object to indicate the HTTP Status Code for a @json_response
# decorator. See @json_response for usage.
STATUS_CODE = object()


def access_control_allow_origin_star(func):
  """Decorator that adds Access-Control-Allow-Origin: * to any HTTPResponse
  allowing cross-site XHR access to the handler."""

  def allow_origin_access_star_wrapper(request, *args, **kwds):
    response = func(request, *args, **kwds)
    response["Access-Control-Allow-Origin"] = "*"
    return response

  return allow_origin_access_star_wrapper


def admin_required(func):
  """Decorator that insists that you're logged in as administratior."""

  def admin_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(
          users.create_login_url(request.get_full_path().encode('utf-8')))
    if not request.user_is_admin:
      return HttpTextResponse(
          'You must be admin in for this function', status=403)
    return func(request, *args, **kwds)

  return admin_wrapper


def editor_required(func):
  """Decorator that insists you own the issue.

  It must appear after issue_required or equivalent, like patchset_required.
  """

  @login_required
  def editor_wrapper(request, *args, **kwds):
    if not request.issue.edit_allowed:
      return HttpTextResponse('You do not own this issue', status=403)
    return func(request, *args, **kwds)

  return editor_wrapper


def image_required(func):
  """Decorator that processes the image argument.

  Attributes set on the request:
   content: a Content entity.
  """

  @patch_required
  def image_wrapper(request, image_type, *args, **kwds):
    content = None
    if image_type == "0":
      content = request.patch.content_key.get()
    elif image_type == "1":
      content = request.patch.patched_content_key.get()
    # Other values are erroneous so request.content won't be set.
    if not content or not content.data:
      return HttpResponseRedirect(django_settings.MEDIA_URL + "blank.jpg")
    request.mime_type = mimetypes.guess_type(request.patch.filename)[0]
    #if not request.mime_type or not request.mime_type.startswith('image/'):
    #  return HttpResponseRedirect(django_settings.MEDIA_URL + "blank.jpg")
    request.content = content
    return func(request, *args, **kwds)

  return image_wrapper


def issue_editor_required(func):
  """Decorator that processes the issue_id argument and insists the user has
  permission to edit it."""

  @login_required
  @issue_required
  def issue_editor_wrapper(request, *args, **kwds):
    if not request.issue.edit_allowed:
      return HttpTextResponse(
          'You do not have permission to edit this issue', status=403)
    return func(request, *args, **kwds)

  return issue_editor_wrapper


def issue_uploader_required(func):
  """Decorator that processes the issue_id argument and insists the user has
  permission to add a patchset to it."""

  @login_required
  @issue_required
  def issue_uploader_wrapper(request, *args, **kwds):
    logging.info('issue_uploader_required checking')
    if not request.issue.upload_allowed:
      logging.info('issue_uploader_required failed')
      return HttpTextResponse(
          'You do not have permission to upload to this issue', status=403)
    return func(request, *args, **kwds)

  return issue_uploader_wrapper


def issue_required(func):
  """Decorator that processes the issue_id handler argument."""

  def issue_wrapper(request, issue_id, *args, **kwds):
    issue = models.Issue.get_by_id(int(issue_id))
    if issue is None:
      return HttpTextResponse(
          'No issue exists with that id (%s)' % issue_id, status=404)
    if issue.private:
      if request.user is None:
        return HttpResponseRedirect(
            users.create_login_url(request.get_full_path().encode('utf-8')))
      if not issue.view_allowed:
        return HttpTextResponse(
            'You do not have permission to view this issue', status=403)
    request.issue = issue
    return func(request, *args, **kwds)

  return issue_wrapper


def json_response(func):
  """Decorator that converts into JSON any returned value that is not an
  HttpResponse. It handles `pretty` URL parameter to tune JSON response for
  either performance or readability.

  If the returned value has an entry whose key is the object |STATUS_CODE|,
  it will be popped out, and will become the status code for the HttpResponse.
  """

  @functools.wraps(func)
  def json_wrapper(request, *args, **kwds):
    data = func(request, *args, **kwds)
    if isinstance(data, HttpResponse):
      return data

    status = 200
    if isinstance(data, collections.MutableMapping):
      status = data.pop(STATUS_CODE, status)

    if request.REQUEST.get('pretty','0').lower() in ('1', 'true', 'on'):
      data = json.dumps(data, indent=2, sort_keys=True)
    else:
      data = json.dumps(data, separators=(',',':'))
    return HttpResponse(data, content_type='application/json; charset=utf-8',
                        status=status)

  return json_wrapper


def login_required(func):
  """Decorator that redirects to the login page if you're not logged in."""

  def login_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(
          users.create_login_url(request.get_full_path().encode('utf-8')))
    return func(request, *args, **kwds)

  return login_wrapper


def patch_filename_required(func):
  """Decorator that processes the patch_id argument."""

  @patchset_required
  def patch_wrapper(request, patch_filename, *args, **kwds):
    patch = models.Patch.query(
        models.Patch.patchset_key == request.patchset.key,
        models.Patch.filename == patch_filename).get()
    if patch is None and patch_filename.isdigit():
      # It could be an old URL which has a patch ID instead of a filename
      patch = models.Patch.get_by_id(int(patch_filename),
                                     parent=request.patchset.key)
    if patch is None:
      return respond(request, 'diff_missing.html',
                     {'issue': request.issue,
                      'patchset': request.patchset,
                      'patch': None,
                      'patchsets': request.issue.patchsets,
                      'filename': patch_filename})
    patch.patchset_key = request.patchset.key
    request.patch = patch
    return func(request, *args, **kwds)

  return patch_wrapper


def patch_required(func):
  """Decorator that processes the patch_id argument."""

  @patchset_required
  def patch_wrapper(request, patch_id, *args, **kwds):
    patch = models.Patch.get_by_id(int(patch_id), parent=request.patchset.key)
    if patch is None:
      return HttpTextResponse(
          'No patch exists with that id (%s/%s)' %
          (request.patchset.key.id(), patch_id),
          status=404)
    patch.patchset_key = request.patchset.key
    request.patch = patch
    return func(request, *args, **kwds)

  return patch_wrapper


def patchset_editor_required(func):
  """Decorator that processes the patchset_id argument and insists you own the
  issue."""

  @patchset_required
  @editor_required
  def patchset_editor_wrapper(request, *args, **kwds):
    return func(request, *args, **kwds)

  return patchset_editor_wrapper


def require_methods(*methods):
  """Returns a decorator which produces an error unless request.method is one
  of |methods|.
  """
  def decorator(func):
    @functools.wraps(func)
    def wrapped(request, *args, **kwds):
      if request.method not in methods:
        allowed = ', '.join(methods)
        rsp = HttpTextResponse('This requires a specific method: %s' % allowed,
                               status=405)
        rsp['Allow'] = allowed
      return func(request, *args, **kwds)
    return wrapped
  return decorator


def task_queue_required(name):
  """Returns a function decorator for a task queue named |name|."""

  def decorate_task_queue(func):

    @functools.wraps(func)
    @require_methods('POST')
    def task_queue_wrapper(request, *args, **kwargs):
      def format_header(head):
        return ('http_' + head).replace('-', '_').upper()

      actual = request.META.get(format_header('X-AppEngine-QueueName'))
      if actual != name:
        logging.error('Task queue name doesn\'t match; %s != %s', actual, name)
        return HttpTextResponse('Can only be run as a task queue.', status=403)
      return func(request, *args, **kwargs)

    return task_queue_wrapper

  return decorate_task_queue


def upload_required(func):
  """Decorator for POST requests from the upload.py script.

  Right now this is for documentation only, but eventually we should
  change this to insist on a special header that JavaScript cannot
  add, to prevent XSRF attacks on these URLs.  This decorator is
  mutually exclusive with @xsrf_required.
  """
  return func


def user_key_required(func):
  """Decorator that processes the user handler argument."""

  def user_key_wrapper(request, user_key, *args, **kwds):
    user_key = urllib.unquote(user_key)
    if '@' in user_key:
      request.user_to_show = users.User(user_key)
    else:
      account = models.Account.get_account_for_nickname(user_key)
      if not account:
        logging.info("account not found for nickname %s" % user_key)
        return HttpTextResponse(
            'No user found with that key (%s)' % urllib.quote(user_key),
            status=404)
      request.user_to_show = account.user
    return func(request, *args, **kwds)

  return user_key_wrapper


def patchset_required(func):
  """Decorator that processes the patchset_id argument."""

  @issue_required
  def patchset_wrapper(request, patchset_id, *args, **kwds):
    patchset = models.PatchSet.get_by_id(
      int(patchset_id), parent=request.issue.key)
    if patchset is None:
      return HttpTextResponse(
          'No patch set exists with that id (%s)' % patchset_id, status=404)
    patchset.issue_key = request.issue.key
    request.patchset = patchset
    return func(request, *args, **kwds)

  return patchset_wrapper


def xsrf_required(func):
  """Decorator to check XSRF token.

  This only checks if the method is POST; it lets other method go
  through unchallenged.  Apply after @login_required and (if
  applicable) @require_methods('POST').  This decorator is mutually exclusive
  with @upload_required.
  """

  def xsrf_wrapper(request, *args, **kwds):
    if request.method == 'POST':
      post_token = request.POST.get('xsrf_token')
      if not post_token:
        return HttpTextResponse('Missing XSRF token.', status=403)
      account = models.Account.current_user_account
      if not account:
        return HttpTextResponse('Must be logged in for XSRF check.', status=403)
      xsrf_token = account.get_xsrf_token()
      if post_token != xsrf_token:
        # Try the previous hour's token
        xsrf_token = account.get_xsrf_token(-1)
        if post_token != xsrf_token:
          msg = [u'Invalid XSRF token.']
          if request.POST:
            msg.extend([u'',
                        u'However, this was the data posted to the server:',
                        u''])
            for key in request.POST:
              msg.append(u'%s: %s' % (key, request.POST[key]))
            msg.extend([u'', u'-'*10,
                        u'Please reload the previous page and post again.'])
          return HttpTextResponse(u'\n'.join(msg), status=403)
    return func(request, *args, **kwds)

  return xsrf_wrapper
