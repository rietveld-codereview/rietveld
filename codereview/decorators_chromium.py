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

"""Decorators for Chromium port of Rietveld."""

import mimetypes
import sha

from google.appengine.api import memcache

from django.http import HttpResponseForbidden

from . import decorators as deco
from . import models_chromium
from . import responses


def binary_required(func):
  """Decorator that processes the content argument.

  Attributes set on the request:
   content: a Content entity.
  """

  @deco.patch_required
  def binary_wrapper(request, content_type, *args, **kwds):
    if content_type == "0":
      content_key = request.patch.content_key
    elif content_type == "1":
      content_key = request.patch.patched_content_key
      if not content_key or not content_key.get().data:
        # The file was not modified. It was likely moved without modification.
        # Return the original file.
        content_key = request.patch.content_key
    else:
      # Other values are erroneous so request.content won't be set.
      return responses.HttpTextResponse(
          'Invalid content type: %s, expected 0 or 1' % content_type,
          status=404)
    request.mime_type = mimetypes.guess_type(request.patch.filename)[0]
    request.content = content_key.get()
    return func(request, *args, **kwds)

  return binary_wrapper


def key_required(func):
  """Decorator that insists that you are using a specific key."""

  @deco.require_methods('POST')
  def key_wrapper(request, *args, **kwds):
    key = request.POST.get('password')
    if request.user or not key:
      return HttpResponseForbidden('You must be admin in for this function')
    value = memcache.get('key_required')
    if not value:
      obj = models_chromium.Key.query().get()
      if not obj:
        # Create a dummy value so it can be edited from the datastore admin.
        obj = models_chromium.Key(hash='invalid hash')
        obj.put()
      value = obj.hash
      memcache.add('key_required', value, 60)
    if sha.new(key).hexdigest() != value:
      return HttpResponseForbidden('You must be admin in for this function')
    return func(request, *args, **kwds)
  return key_wrapper
