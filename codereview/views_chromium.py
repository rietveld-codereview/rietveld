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
import datetime
import logging
import os
import re
import sha

from google.appengine.api import memcache
from google.appengine.ext import db

from django import forms
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.utils.html import strip_tags
from django.utils import simplejson as json

import cpplint
import cpplint_chromium
import engine
import models
import models_chromium
import patching
import views
from views import issue_editor_required, login_required
from views import patch_required, patchset_required, post_required
from views import respond, reverse, xsrf_required


### Forms ###


class EditFlagsForm(forms.Form):

  last_patchset = forms.IntegerField(widget=forms.HiddenInput())
  commit = forms.BooleanField(required=False)
  builders = forms.CharField(max_length=255, required=False)


### Utility functions ###


def key_required(func):
  """Decorator that insists that you are using a specific key."""

  @post_required
  def key_wrapper(request, *args, **kwds):
    key = request.POST.get('password')
    if request.user or not key:
      return HttpResponseForbidden('You must be admin in for this function')
    value = memcache.get('key_required')
    if not value:
      obj = models_chromium.Key.all().get()
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


def string_to_datetime(text):
  """Parses a string into datetime including microseconds.

  It parses the standard str(datetime.datetime()) format.
  """
  items = text.split('.', 1)
  result = datetime.datetime.strptime(items[0], '%Y-%m-%d %H:%M:%S')
  if len(items) > 1:
    result = result.replace(microsecond=int(items[1]))
  return result


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


def unpack_result(result):
  """Buildbot may pack results with multiple layer of lists."""
  while isinstance(result, (list, tuple)):
    result = result[0]
  return result


def handle_build_started(base_url, timestamp, packet, payload):
  build = payload['build']
  # results should always be absent.
  result = build.get('results', [-1])
  return inner_handle(base_url, timestamp, packet, result, build['properties'])


def handle_build_finished(base_url, timestamp, packet, payload):
  build = payload['build']
  # results is omitted if success so insert it manually.
  result = build.get('results', [models.TryJobResult.SUCCESS])
  return inner_handle(base_url, timestamp, packet, result, build['properties'])


def handle_step_finished(base_url, timestamp, packet, payload):
  result = unpack_result(payload['step'].get('results', None))
  if result in models.TryJobResult.OK:
    # We don't want to mark the try job as success before it's completed!
    result = -1
  return inner_handle(
      base_url, timestamp, packet, result, payload['properties'])


def inner_handle(base_url, timestamp, packet, result, properties):
  """Handles one event coming from HttpStatusPush and update the relevant
  TryJobResult object.

  Three cases can arrive:
  - A new try job was started, initiated from svn/http request so no
    TryJobResult exists. No key is passed through, a new entity must be created.
  - A new try job was started from a TryJobResult.result=TRYPENDING. Then the
    key is passed through since the TryJobResult object exists.
  - An existing try job is updated. Most frequent case.
  """
  issue = None
  patchset = None
  try:
    properties = dict((name, value) for name, value, _ in properties)
    revision = str(properties['revision'])
    buildername = properties['buildername']
    buildnumber = int(properties['buildnumber'])
    slavename = properties['slavename']
    # Keep them last.
    issue = int(properties['issue'])
    patchset = int(properties['patchset'])
    project = packet['project']
  except (KeyError, TypeError, ValueError), e:
    logging.error('Failure when parsing properties: %s' % e)
  if not issue or not patchset:
    logging.error('Bad packet, no issue or patchset: %r' % properties)
    return

  result = unpack_result(result)
  issue_key = db.Key.from_path('Issue', issue)
  patchset_key = db.Key.from_path('PatchSet', patchset, parent=issue_key)
  # Verify the key validity by getting the instance.
  if db.get(patchset_key) == None:
    logging.warn('Bad issue/patch id: %s/%s' % (issue, patchset))
    return

  keyname = '%s-%s-%s-%s' % (issue, patchset, buildername, buildnumber)
  def tx_try_job_result():
    try_obj = models.TryJobResult.all(
        ).ancestor(patchset_key
        ).filter('builder =', buildername
        ).filter('buildnumber =', buildnumber).get()
    url = '%sbuildstatus?builder=%s&number=%s' % (
        base_url, buildername, buildnumber)
    if try_obj is None:
      try_obj = models.TryJobResult(
          parent=patchset_key,
          url=url,
          result=result,
          builder=buildername,
          slave=slavename,
          buildnumber=buildnumber,
          revision=revision,
          # TODO(maruel): Missing data.
          reason='',
          project=project,
          timestamp=timestamp,
          )
      logging.info('Creating instance %s' % keyname)
    else:
      # Update result only if relevant.
      if (models.TryJobResult.result_priority(result) >
          models.TryJobResult.result_priority(try_obj.result)):
        try_obj.result = result
      if try_obj.project and try_obj.project != project:
        logging.critical(
            'Project for %s didn\'t match: was %s, setting %s' % (keyname,
              try_obj.project, project))
      try_obj.project = project
      # Update the rest unconditionally.
      try_obj.timestamp = timestamp
      try_obj.url = url
      try_obj.revision = revision
      try_obj.slave = slavename
      try_obj.buildnumber = buildnumber
      logging.info(
          'Updated %s-%s-%s-%s: %s' % (
            issue, patchset, buildername, buildnumber, try_obj.result))
    try_obj.put()
    return True
  if not db.run_in_transaction(tx_try_job_result):
    logging.error('Failed to update %s' % keyname)
    return False
  return True


HANDLER_MAP = {
  'buildStarted': handle_build_started,
  'buildFinished': handle_build_finished,
  'stepFinished': handle_step_finished,
}


def process_status_push(packets_json, base_url):
  """Processes all the packets coming from HttpStatusPush."""
  packets = sorted(json.loads(packets_json),
                   key=lambda packet: string_to_datetime(packet['timestamp']))
  for packet in packets:
    timestamp = string_to_datetime(packet['timestamp'])
    event = packet.get('event', '')
    if event not in HANDLER_MAP:
      logging.warn('Stop sending events of type %s' % event)
      continue
    if 'payload' in packet:
      # 0.8.x
      payload = packet.pop('payload')
    elif 'payload_json' in packet:
      # 0.7.12
      payload = json.loads(packet.pop('payload_json'))
    else:
      logging.warn('Invalid packet %r' % packet)
      continue
    HANDLER_MAP[event](base_url, timestamp, packet, payload)


### View handlers ###

@issue_editor_required
@xsrf_required
def edit_flags(request):
  """/<issue>/edit_flags - Edit issue's flags."""
  def get_existing_builders(last_patchset):
    return dict((job.builder, job) for job in
                models.TryJobResult.all().ancestor(last_patchset))

  last_patchset = models.PatchSet.all().ancestor(
      request.issue).order('-created').get()
  if not last_patchset:
    return HttpResponseForbidden('Can only modify flags on last patchset',
        content_type='text/plain')

  if request.method == 'GET':
    existing_builders = get_existing_builders(last_patchset)
    initial_builders = (', '.join(existing_builders.iterkeys()) or
                        'win, mac, linux')

    form = EditFlagsForm(initial={
        'last_patchset': last_patchset.key().id(),
        'commit': request.issue.commit,
        'builders': initial_builders})
    return views.respond(request,
                         'edit_flags.html',
                         {'issue': request.issue,'form': form})

  form = EditFlagsForm(request.POST)
  if not form.is_valid():
    return HttpResponseBadRequest('Invalid POST arguments',
        content_type='text/plain')
  if (form.cleaned_data['last_patchset'] != last_patchset.key().id()):
    return HttpResponseForbidden('Can only modify flags on last patchset',
        content_type='text/plain')

  if 'commit' in form.cleaned_data:
    request.issue.commit = form.cleaned_data['commit']
    request.issue.put()

  if 'builders' in form.cleaned_data:
    def txn():
      jobs_to_save = []
      jobs_to_delete = []

      new_builders = filter(None, map(unicode.strip,
                                      form.cleaned_data['builders'].split(',')))
      existing_builders = get_existing_builders(last_patchset)

      # Figure out which builders we need to remove.  Only remove any that are
      # still pending.
      for existing_builder, existing_job in existing_builders.iteritems():
        if (existing_builder not in new_builders and
            existing_job.result == models.TryJobResult.TRYPENDING):
          jobs_to_delete.append(existing_job)

      # Add any new builders.
      for builder in new_builders:
        if builder not in existing_builders:
          try_job = models.TryJobResult(parent=last_patchset,
                                        url='',  # Will be set later
                                        result=models.TryJobResult.TRYPENDING,
                                        builder=builder)
          jobs_to_save.append(try_job)

      # Commit everything.
      db.delete(jobs_to_delete)
      db.put(jobs_to_save)
    db.run_in_transaction(txn)

  return HttpResponse('OK', content_type='text/plain')


@key_required
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


@key_required
def status_listener(request):
  """Receives Buildbot events and keeps the try jobs results.

  Defer the actual work to a defer to keep this handler very fast.
  """
  packets = request.POST.get('packets')
  if not packets:
    return HttpResponseBadRequest('No packets given')
  base_url = request.POST.get('base_url')
  if not base_url:
    return HttpResponseBadRequest('No base url given')
  # Using deferred means that we could lose some packets if processing fails.
  # Until a good solution is found for this problem, process the packets
  # synchronously.
  #deferred.defer(process_status_push, packets, base_url)
  process_status_push(packets, base_url)
  return HttpResponse('OK')


@views.json_response
def get_pending_try_patchsets(request):
  limit = int(request.GET.get('limit', '10'))
  if limit > 1000:
    limit = 1000

  q = models.TryJobResult.all().filter(
      'result =', models.TryJobResult.TRYPENDING).order('timestamp')
  return [job.to_dict() for job in q.fetch(limit)]
