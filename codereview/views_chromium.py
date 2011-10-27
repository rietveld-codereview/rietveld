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

"""Views for Chromium port of Rietveld."""

import cgi
import logging
import os
import re
import sha

from google.appengine.api import users
from google.appengine.ext import db

from django import forms
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.utils.html import strip_tags

import cpplint
import cpplint_chromium
import engine
import models_chromium
import patching
import views
from views import issue_editor_required, login_required
from views import patch_required, patchset_required, post_required
from views import respond, reverse, xsrf_required, IS_DEV


### Forms ###


class EditFlagsForm(forms.Form):

  last_patchset = forms.IntegerField(widget=forms.HiddenInput())
  commit = forms.BooleanField(required=False)


### Utility functions ###


def _lint_patch(patch):
  patch.lint_error_count = 0
  patch.lint_errors = {}
  if patch.is_binary or patch.no_base_file:
    return False

  if os.path.splitext(patch.filename)[1] not in ['.c', '.cc', '.cpp', '.h']:
    return False

  try:
    patch.get_patched_content()
  except engine.FetchError:
    return False

  patch.parsed_lines = patching.ParsePatchToLines(patch.lines)
  if patch.parsed_lines is None:
    return False

  new_line_numbers = set()
  for old_line_no, new_line_no, _ in patch.parsed_lines:
    if old_line_no == 0 and new_line_no != 0:
      # Line is newly added, so check lint errors in it.
      new_line_numbers.add(new_line_no)

  def error(_filename, linenum, _category, _confidence, message):
    if linenum in new_line_numbers:
      patch.lint_errors.setdefault(linenum, []).append(message)

  file_extension = os.path.splitext(patch.filename)[1]
  lines = patch.get_patched_content().text.splitlines()
  extra_check_functions = [cpplint_chromium.CheckPointerDeclarationWhitespace]
  cpplint.ProcessFileData(
      patch.filename, file_extension, lines, error, extra_check_functions)

  return True


### View handlers ###

@post_required
@issue_editor_required
@xsrf_required
def edit_flags(request):
  """/<issue>/edit_flags - Edit issue's flags."""
  form = EditFlagsForm(request.POST)
  if not form.is_valid():
    return HttpResponseBadRequest('Invalid POST arguments',
        content_type='text/plain')
  # TODO: Request keys only.
  patchsets = list(request.issue.patchset_set.order('created'))
  if (not patchsets or
      form.cleaned_data['last_patchset'] != patchsets[-1].key().id()):
    return HttpResponseForbidden('Can only modify flags on last patchset',
        content_type='text/plain')
  if 'commit' in form.cleaned_data:
    request.issue.commit = form.cleaned_data['commit']
    request.issue.put()
  return HttpResponse('OK', content_type='text/plain')


@post_required
@patchset_required
def upload_build_result(request):
  """/<issue>/upload_build_result/<patchset> - Set build result for a patchset.

  Used to upload results from a build made with the patchset on a given
  platform.
  """
  form = views.UploadBuildResult(request.POST, request.FILES)
  if not form.is_valid():
    return HttpResponse('ERROR: Upload build result errors:\n%s' %
                        repr(form.errors), content_type='text/plain')
  # Use a backdoor password for automated builds to be able to push data here.
  if sha.new(form.cleaned_data.get('password', '')).hexdigest() != \
      '980954318b0845754d89cd5410edbace13487356':
    if request.user is None:
      if False and IS_DEV:
        request.user = users.User(request.POST.get('user', 'test@example.com'))
      else:
        return HttpResponse('Error: Login required', status=401)
    if request.user != request.issue.owner:
      return HttpResponse('ERROR: You (%s) don\'t own this issue (%s).' %
                          (request.user, request.issue.key().id()))
  # Do we already have build results for this patchset on this platform?
  platform_id = strip_tags(form.cleaned_data['platform_id'])
  patchset = request.patchset
  existing = False
  index = None
  for index, build_result in enumerate(patchset.build_results):
    if (build_result.split(views.UploadBuildResult.SEPARATOR, 2)[0] ==
        platform_id):
      existing = True
      break
  if existing:
    if form.cleaned_data['status']:
      patchset.build_results[index] = str(form)
      message = 'Updated existing result.'
    else:
      # An empty status means remove this build result.
      patchset.build_results.pop(index)
      message = 'Removed existing result.'
  elif form.cleaned_data['status']:
    patchset.build_results.append(str(form))
    message = 'Adding new status result.'
  else:
    message = 'Not adding empty status result.'

  patchset.put()
  return HttpResponse(message, content_type='text/plain')


@patchset_required
def get_build_results(request):
  """/<issue>/get_build_results/<patchset> - Get build results for a patchset.

  Used to retrieve the build results for a given patchset. The format of the
  returned data is as follows:
    <platform_id>|<status>|<details_url>
    <platform_id>|<status>|<details_url>
    etc...
  """
  response = ""
  for build_result in request.patchset.build_results:
    response = "%s%s\n" % (response, str(build_result))
  return HttpResponse(response, content_type='text/plain')


@login_required
@xsrf_required
def conversions(request):
  """/conversions - Show and edit the list of base=>source code URL maps."""
  rules = models_chromium.UrlMap.gql('ORDER BY base_url_template')
  if request.method != 'POST':
    return respond(request, 'conversions.html', {
            'rules': rules})

  if (not request.user.email().endswith('@chromium.org') and
      not request.user.email().endswith('@google.com')):
    # TODO(vbendeb) this domain name should be a configuration item. Or maybe
    # only admins should be allowed to modify the conversions table.
    warning = 'You are not authorized to modify the conversions table.'
    return respond(request, 'conversions.html', {
        'warning': warning,
        'rules': rules,
        })

  for key, _ in request.POST.iteritems():
    if key.startswith('del '):
      del_key = key[4:]
      urlmap = models_chromium.UrlMap.gql(
          'WHERE base_url_template = :1', del_key)
      if not urlmap:
        logging.error('No map for %s found' % del_key)
        continue
      db.delete(urlmap)
  base_url = request.POST.get('base_url_template')
  src_url = request.POST.get('source_code_url_template')
  if base_url and src_url:
    warning = ''
    try:
      re.compile(r'%s' % base_url)
    except re.error, err:
      warning = 'Regex error "%s"' % err
    if not warning:
      urlmap = models_chromium.UrlMap.gql(
          'WHERE base_url_template = :1', base_url)
      if urlmap.count():
        warning = 'Attempt to add a duplicate Base Url'
    if warning:
      rules = models_chromium.UrlMap.gql('ORDER BY base_url_template')
      return respond(request, 'conversions.html', {
         'warning': warning,
         'rules': rules,
         'base_url': base_url,
         'src_url': src_url
         })

    new_map = models_chromium.UrlMap(
        base_url_template=base_url, source_code_url_template=src_url)
    logging.info(new_map)
    new_map.put()
  return HttpResponseRedirect(reverse(conversions))


@patchset_required
def lint(request):
  """/lint/<issue>_<patchset> - Lint a patch set."""
  patches = list(request.patchset.patch_set)
  for patch in patches:
    if not _lint_patch(patch):
      continue

    for line in patch.lint_errors:
      patch.lint_error_count += len(patch.lint_errors[line])
  db.put(patches)

  return HttpResponse('Done', content_type='text/plain')


@patch_required
def lint_patch(request):
  """/<issue>/lint/<patchset>/<patch> - View lint results for a patch."""
  if not _lint_patch(request.patch):
    return HttpResponseNotFound('Can\'t lint file')

  result = [
      ( '<html><head>'
        '<link type="text/css" rel="stylesheet" href="/static/styles.css" />'
        '</head><body>'),
      ( '<div class="code" style="margin-top: .8em; display: table; '
        'margin-left: auto; margin-right: auto;">'),
      '<table style="padding: 5px;" cellpadding="0" cellspacing="0"'
  ]
  error_count = 0
  for old_line_no, new_line_no, line in request.patch.parsed_lines:
    result.append('<tr><td class="udiff">%s</td></tr>' % cgi.escape(line))
    if old_line_no == 0 and new_line_no in request.patch.lint_errors:
      for error in request.patch.lint_errors[new_line_no]:
        result.append('<tr><td style="color:red">%s</td></tr>' % error)
        error_count += 1

  result.append('</table></div>')
  result.append('</body></html>')

  if request.patch.lint_error_count != error_count:
    request.patch.lint_error_count = error_count
    request.patch.put()

  return HttpResponse(''.join(result))
