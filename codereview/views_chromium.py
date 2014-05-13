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

from google.appengine.api import taskqueue
from google.appengine.ext import db
from google.appengine.ext import ndb
from google.appengine.runtime import DeadlineExceededError

from django import forms
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.http import HttpResponseServerError
from django.utils import simplejson as json

from codereview import cpplint
from codereview import cpplint_chromium
from codereview import decorators as deco
from codereview import decorators_chromium as deco_cr
from codereview import exceptions
from codereview import models
from codereview import models_chromium
from codereview import patching
from codereview import responses
from codereview import views


### Forms ###


class EditFlagsForm(forms.Form):
  last_patchset = forms.IntegerField(widget=forms.HiddenInput())
  commit = forms.BooleanField(required=False)
  builders = forms.CharField(max_length=16*1024, required=False)


class TryPatchSetForm(forms.Form):
  reason = forms.CharField(max_length=255)
  revision = forms.CharField(max_length=40, required=False)
  clobber = forms.BooleanField(required=False)
  master = forms.CharField(max_length=255, required=False)
  builders = forms.CharField(max_length=16*1024)


class TryserversForm(forms.Form):
  base_url = forms.CharField(
      max_length=255,
      help_text='The Base URL of issues that should use the specified '
                'tryserver. Example: "http://src.chromium.org/svn/trunk/src/"')
  json_urls = forms.CharField(
      max_length=511,
      help_text='Comma separated list of tryserver JSON URLs. Example: '
                '"http://build.chromium.org/p/tryserver.chromium/json/builders'
                ',http://build.chromium.org/p/tryserver.chromium.linux/json/'
                'builders"')
  tryserver_name = forms.CharField(
      max_length=255,
      help_text='The tryserver name from DefaultBuilderList. '
                'Example: "tryserver.chromium"')


### Utility functions ###


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
  except exceptions.FetchError:
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
  return inner_handle(
      build.get('reason', ''), base_url, timestamp, packet, result,
      build.get('properties', []))


def handle_build_finished(base_url, timestamp, packet, payload):
  build = payload['build']
  # results is omitted if success so insert it manually.
  result = build.get('results', [models.TryJobResult.SUCCESS])
  return inner_handle(
      build.get('reason', ''), base_url, timestamp, packet, result,
      build.get('properties', []))


def inner_handle(reason, base_url, timestamp, packet, result, properties):
  """Handles one event coming from HttpStatusPush and update the relevant
  TryJobResult object.

  Three cases can arrive:
  - A new try job was started, initiated from svn/http request so no
    TryJobResult exists. No key is passed through, a new entity must be created.
  - A new try job was started from a TryJobResult.result=TRYPENDING. Then the
    key is passed through since the TryJobResult object exists.
  - An existing try job is updated. Most frequent case.
  """
  issue_id = None
  patchset_id = None
  parent_buildername = None
  parent_buildnumber = None
  buildername = None
  buildnumber = None
  try:
    properties = dict((name, value) for name, value, _ in properties)
    revision = str(properties['revision'])
    buildername = properties['buildername']
    buildnumber = int(properties['buildnumber'])
    slavename = properties['slavename']
    # The try job key property will only be present for try jobs started from
    # rietveld itself, either from the webui or from the try_patchset endpoint.
    try_job_key = properties.get('try_job_key')
    # Issue and patchset might be missing in triggered jobs.
    issue_id = int(properties.get('issue', 0))
    patchset_id = int(properties.get('patchset', 0))

    # Keep them last.
    # The parent_XXX means that this is a build triggered from another build,
    # for example a build that would create builds artifacts trigger another
    # build that run test on a separate slave.
    if (properties.get('parent_buildername') and
        properties.get('parent_buildnumber')):
      parent_buildnumber = int(properties['parent_buildnumber'])
      parent_buildername = properties['parent_buildername']
      logging.info(
          'Dereferencing from %s/%d' % (parent_buildername, parent_buildnumber))
    project = packet['project']
  except (KeyError, TypeError, ValueError), e:
    logging.warn(
        'Failure when parsing properties: %s; i:%s/%s b:%s/%s' %
        (e, issue_id, patchset_id, buildername, buildnumber))

  # When issue or patchset are missing in a triggered job, try to
  # recover those from the parent build.  Note that this is not
  # reliable, as build numbers are not unique, and is not super
  # efficient since this adds yet another datastore request.
  if not (issue_id and patchset_id) and parent_buildername:
    parent_build_key = models.TryJobResult.query(
      models.TryJobResult.builder == parent_buildername,
      models.TryJobResult.buildnumber == parent_buildnumber).get(keys_only=True)
    if parent_build_key:
      # Dereference the parent Patchset object. Luckily, this is in the key.
      patchset_key = parent_build_key.parent()
      if not patchset:
        patchset_id = patchset_key.id()
      if not issue:
        issue_id = patchset_key.parent().id()
      logging.info('Dereferenced %d/%d' % (issue_id, patchset_id))
      try_job_key = None
    else:
      logging.warn('Failed to find deferenced build')

  if not issue_id or not patchset_id:
    logging.warn('Bad packet, no issue or patchset: %r' % properties)
    return

  result = unpack_result(result)
  issue_key = ndb.Key(models.Issue, issue_id)
  patchset_key = ndb.Key(models.PatchSet, patchset_id, parent=issue_key)
  # Verify the key validity by getting the instance.
  if patchset_key.get() == None:
    logging.warn('Bad issue/patch id: %s/%s' % (issue_id, patchset_id))
    return

  # Used only for logging.
  keyname = '%s-%s-%s-%s' % (issue_id, patchset_id, buildername, buildnumber)

  def tx_try_job_result():
    if try_job_key:
      try_obj = models.TryJobResult.get(try_job_key)
      # If a key is given, then we must only update that try job.
      if not try_obj:
        logging.error('Try job not found by key=%s %s', try_job_key, keyname)
        return False
    else:
      try_obj = models.TryJobResult.query(
          models.TryJobResult.builder == buildername,
          models.TryJobResult.buildnumber == buildnumber,
          ancestor=patchset_key).get()

    if buildername and buildnumber >= 0:
      url = '%sbuilders/%s/builds/%s' % (
          base_url, buildername, buildnumber)
    else:
      url = ''
    if try_obj is None:
      try_obj = models.TryJobResult(
          parent=patchset_key,
          reason=reason,
          url=url,
          result=result,
          builder=buildername,
          parent_name=parent_buildername,
          slave=slavename,
          buildnumber=buildnumber,
          revision=revision,
          project=project,
          clobber=bool(properties.get('clobber')),
          tests=properties.get('testfilter') or [])
      logging.info('Creating instance %s' % keyname)
    else:
      # Update result only if relevant.
      if (models.TryJobResult.result_priority(result) >
          models.TryJobResult.result_priority(try_obj.result)):
        logging.info('Setting result: new=%s old=%s %s', result, try_obj.result,
                     keyname)
        try_obj.result = result
      else:
        logging.info('Result irrelevant: new=%s old=%s %s', result,
                     try_obj.result, keyname)
        return True

      if try_obj.project and try_obj.project != project:
        logging.critical(
            'Project for %s didn\'t match: was %s, setting %s' % (keyname,
              try_obj.project, project))
      try_obj.project = project
      # Use timestamp from AppEngine, which always uses UTC.
      # This makes it possible to reliably compare timestamps (including case
      # of calculating how old is the result stored in the datastore).
      try_obj.timestamp = datetime.datetime.now()
      # Update the rest unconditionally.
      try_obj.url = url
      try_obj.revision = revision
      try_obj.slave = slavename
      try_obj.buildnumber = buildnumber
      logging.info(
          'Updated %s: %s' % (keyname, try_obj.result))
    try_obj.put()
    return True
  if not ndb.transaction(tx_try_job_result):
    logging.error('Failed to update %s' % keyname)
    return False
  return True


HANDLER_MAP = {
  'buildStarted': handle_build_started,
  'buildFinished': handle_build_finished,
}


def process_status_push(packets_json, base_url):
  """Processes all the packets coming from HttpStatusPush."""
  packets = sorted(json.loads(packets_json),
                   key=lambda packet: string_to_datetime(packet['timestamp']))
  logging.info('Processing %d packets' % len(packets))
  done = 0
  try:
    for packet in packets:
      timestamp = string_to_datetime(packet['timestamp'])
      event = packet.get('event', '')
      if event not in HANDLER_MAP:
        logging.warn('Stop sending events of type %s' % event)
        continue
      if 'payload' not in packet:
        logging.warn('Invalid packet %r' % packet)
        continue
      HANDLER_MAP[event](base_url, timestamp, packet, packet.pop('payload'))
      done += 1
  finally:
    logging.info('Processed %d packets' % done)


def _is_job_valid(job):
  """Determines if a pending try job result is valid or not.

  Pending try job results are those with result is set to
  models.TryJobResult.TRYPENDING.  These jobs are invalid if:

  - their associated issue is already committed, and
  - their associated PatchSet is no longer the latest in the issue.

  Args:
    job: an instance of models.TryJobResult.

  Returns:
    True if the pending try job is invalid, False otherwise.
  """
  if job.result == models.TryJobResult.TRYPENDING:
    patchset = job.parent()
    issue = patchset.issue.get()

    if issue.closed:
      return False

    last_patchset_key = models.PatchSet.query(ancestor=issue.key).order(
      -models.PatchSet.created).get(keys_only=True)
    if last_patchset_key != patchset.key:
      return False

  return True


### View handlers ###

@deco.issue_editor_required
@deco.xsrf_required
def edit_flags(request):
  """/<issue>/edit_flags - Edit issue's flags."""
  last_patchset = models.PatchSet.query(ancestor=request.issue.key).order(
    -models.PatchSet.created).get()
  if not last_patchset:
    return HttpResponseForbidden('Can only modify flags on last patchset',
        content_type='text/plain')
  if request.issue.closed:
    return HttpResponseForbidden('Can not modify flags for a closed issue',
        content_type='text/plain')

  if request.method == 'GET':
    # TODO(maruel): Have it set per project.
    initial_builders = 'win_rel, mac_rel, linux_rel'
    form = EditFlagsForm(initial={
        'last_patchset': last_patchset.key.id(),
        'commit': request.issue.commit,
        'builders': initial_builders})

    return responses.respond(request,
                         'edit_flags.html',
                         {'issue': request.issue, 'form': form})

  form = EditFlagsForm(request.POST)
  if not form.is_valid():
    return HttpResponseBadRequest('Invalid POST arguments',
        content_type='text/plain')
  if (form.cleaned_data['last_patchset'] != last_patchset.key.id()):
    return HttpResponseForbidden('Can only modify flags on last patchset',
        content_type='text/plain')

  if 'commit' in request.POST:
    request.issue.commit = form.cleaned_data['commit']
    user_email = request.user.email().lower()
    if (request.issue.commit and  # Add as reviewer if setting, not clearing.
        user_email != request.issue.owner.email() and
        user_email not in request.issue.reviewers and
        user_email not in request.issue.collaborator_emails()):
      request.issue.reviewers.append(request.user.email())
    # Update the issue with the checking/unchecking of the CQ box but reduce
    # spam by not emailing users.
    action = 'checked' if request.issue.commit else 'unchecked'
    commit_checked_msg = 'The CQ bit was %s by %s' % (action, user_email)
    views.make_message(request, request.issue, commit_checked_msg,
                       send_mail=False).put()
    request.issue.put()

  if 'builders' in request.POST:
    def txn():
      jobs_to_save = []
      new_builders = filter(None, map(unicode.strip,
                                      form.cleaned_data['builders'].split(',')))

      # Add any new builders.
      for builder in new_builders:
        mastername, buildername = builder.split(':', 1)
        try_job = models.TryJobResult(parent=last_patchset.key,
                                      reason='',
                                      result=models.TryJobResult.TRYPENDING,
                                      master=mastername,
                                      builder=buildername,
                                      revision='',
                                      clobber=False)
        jobs_to_save.append(try_job)

      # Commit everything.
      ndb.put_multi(jobs_to_save)
    ndb.transaction(txn)

  return HttpResponse('OK', content_type='text/plain')


@deco.login_required
@deco.xsrf_required
def conversions(request):
  """/conversions - Show and edit the list of base=>source code URL maps."""
  rules = models_chromium.UrlMap.gql('ORDER BY base_url_template')
  if request.method != 'POST':
    return responses.respond(request, 'conversions.html', {
            'rules': rules})

  if not models_chromium.UrlMap.user_can_edit(request.user):
    # TODO(vbendeb) this domain name should be a configuration item. Or maybe
    # only admins should be allowed to modify the conversions table.
    warning = 'You are not authorized to modify the conversions table.'
    return responses.respond(request, 'conversions.html', {
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
      return responses.respond(request, 'conversions.html', {
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


@deco.patchset_required
def lint(request):
  """/lint/<issue>_<patchset> - Lint a patch set."""
  patches = list(request.patchset.patches)
  for patch in patches:
    if not _lint_patch(patch):
      continue

    for line in patch.lint_errors:
      patch.lint_error_count += len(patch.lint_errors[line])
  ndb.put_multi(patches)

  return HttpResponse('Done', content_type='text/plain')


@deco.patch_required
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


@deco_cr.key_required
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


@deco_cr.binary_required
def download_binary(request):
  """/<issue>/binary/<patchset>/<patch>/<content>

  Return patch's binary content.  If the patch is not binary, an empty stream
  is returned.  <content> may be 0 for the base content or 1 for the new
  content.  All other values are invalid.
  """
  response = HttpResponse(request.content.data, content_type=request.mime_type)
  filename = re.sub(
      r'[^\w\.]', '_', request.patch.filename.encode('ascii', 'replace'))
  response['Content-Disposition'] = 'attachment; filename="%s"' % filename
  return response


def update_default_builders(_request):
  """/restricted/update_default_builders - Updates list of default builders."""
  models_chromium.TryserverBuilders.refresh()
  return HttpResponse('success', content_type='text/plain')


@deco.admin_required
@deco.xsrf_required
def update_tryservers(request):
  """/restricted/update_tryservers - Sets Tryserver information.

  Sets JSON URLs and Tryserver name to a specified base URL.
  """
  if request.method == 'GET':
    return responses.respond(request, 'update_tryservers.html',
                   {'form': TryserversForm()})

  form = TryserversForm(request.POST)
  if not form.is_valid():
    return responses.HttpTextResponse('Invalid arguments', status=400)

  base_url = form.cleaned_data['base_url']
  json_urls_str = form.cleaned_data['json_urls']
  tryserver_name = form.cleaned_data['tryserver_name']

  try:
    json_urls = json_urls_str.split(',')
    base_url_tryserver = models_chromium.BaseUrlTryServer(
        key_name=base_url,
        json_urls=json_urls,
        tryserver_name=tryserver_name)
    base_url_tryserver.put()
    content = 'Updated successfully.\n\n'
    content += 'base_url: %s\n' % base_url
    content += 'json_urls: %s\n' % json_urls
    content += 'tryserver_name: %s' % tryserver_name
  except DeadlineExceededError:
    return HttpResponseServerError('Deadline exceeded')

  logging.info(content)
  return HttpResponse(content, content_type='text/plain')


def delete_old_pending_jobs(_request):
  """/restricted/delete_old_pending_jobs

  Trigger task to delete old pending jobs.
  """
  cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
  cutoff_date_str = cutoff_date.strftime("DATETIME(%Y-%m-%d %H:%M:%S)")
  cursor = ''
  limit = 100
  offset = 0
  taskqueue.add(
      url=reverse(delete_old_pending_jobs_task),
      params={
        'cursor': cursor,
        'cutoff_date': cutoff_date_str,
        'limit': str(limit),
        'offset': str(offset),
      },
      queue_name='delete-old-pending-jobs-task')
  msg = 'Trigger done at %s' % cutoff_date_str
  logging.info(msg)
  return HttpResponse(msg, content_type='text/plain')


def delete_old_pending_jobs_task(request):
  """/restricted/delete_old_pending_jobs_task - Deletes old pending jobs.

  Delete invalid pending try jobs older than a day old.
  """
  encoded_cursor = request.POST.get('cursor')
  cutoff_date_str = request.POST.get('cutoff_date')
  cutoff_date = datetime.datetime.strptime(
      cutoff_date_str, "DATETIME(%Y-%m-%d %H:%M:%S)")
  limit = int(request.POST.get('limit'))
  offset = int(request.POST.get('offset'))

  q = models.TryJobResult.query(
      models.TryJobResult.result == models.TryJobResult.TRYPENDING).order(
      models.TryJobResult.timestamp)
  cursor = None
  if encoded_cursor:
    cursor = datastore_query.Cursor(urlsafe=encoded_cursor)

  logging.info('cutoffdate=%s, limit=%d, offset=%d cursor=%s', cutoff_date_str,
      limit, offset, cursor)
  items, next_cursor, _ = q.fetch_page(limit, start_cursor=cursor)
  if not items:
    msg = 'Iteration done'
    logging.info(msg)
    return HttpResponse(msg, content_type='text/plain')

  # Enqueue the next one right away.
  taskqueue.add(
      url=reverse(delete_old_pending_jobs_task),
      params={
        'cursor': next_cursor.urlsafe() if next_cursor else '',
        'cutoff_date': cutoff_date_str,
        'limit': str(limit),
        'offset': str(offset + len(items)),
      },
      queue_name='delete-old-pending-jobs-task')

  count = 0
  for job in items:
    if not _is_job_valid(job):
      if job.timestamp <= cutoff_date:
        job.delete()
        count += 1
  msg = '%d pending jobs purged out of %d' % (count, len(items))
  logging.info(msg)
  return HttpResponse(msg, content_type='text/plain')


@deco.require_methods('POST')
@deco.xsrf_required
@deco.patchset_required
@deco.json_response
def try_patchset(request):
  """/<issue>/try/<patchset> - Add a try job for the given patchset."""
  # Only allow trying the last patchset of an issue.
  last_patchset_key = models.PatchSet.query(ancestor=request.issue.key).order(
    -models.PatchSet.created).get(keys_only=True)
  if last_patchset_key != request.patchset.key:
    content = (
        'Patchset %d/%d invalid: Can only try the last patchset of an issue.' %
        (request.issue.key.id(), request.patchset.key.id()))
    logging.info(content)
    return HttpResponseBadRequest(content, content_type='text/plain')

  form = TryPatchSetForm(request.POST)
  if not form.is_valid():
    return HttpResponseBadRequest('Invalid POST arguments',
                                  content_type='text/plain')
  reason = form.cleaned_data['reason']
  revision = form.cleaned_data['revision']
  clobber = form.cleaned_data['clobber']
  master = form.cleaned_data['master']

  try:
    builders = json.loads(form.cleaned_data['builders'])
  except json.JSONDecodeError:
    content = 'Invalid json for builder spec: ' + form.cleaned_data['builders']
    logging.error(content)
    return HttpResponseBadRequest(content, content_type='text/plain')

  if not isinstance(builders, dict):
    content = 'Invalid builder spec: ' + form.cleaned_data['builders']
    logging.error(content)
    return HttpResponseBadRequest(content, content_type='text/plain')

  logging.debug(
      'clobber=%s\nrevision=%s\nreason=%s\nmaster=%s\nbuilders=%s',
      clobber, revision, reason, master, builders)

  def txn():
    # Get list of existing pending try jobs for this patchset.  Don't create
    # duplicates here.
    patchset = models.PatchSet.get(last_patchset_key)

    jobs_to_save = []
    for builder, tests in builders.iteritems():
      try_job = models.TryJobResult(parent=patchset.key,
                                    result=models.TryJobResult.TRYPENDING,
                                    master=master,
                                    builder=builder,
                                    revision=revision,
                                    clobber=clobber,
                                    tests=tests,
                                    reason=reason,
                                    requester=request.user)
      jobs_to_save.append(try_job)

    if jobs_to_save:
      ndb.put_multi(jobs_to_save)
    return dict((j.builder, j.key.id()) for j in jobs_to_save)
  job_saved = ndb.transaction(txn)
  content = 'Started %d jobs.' % len(job_saved)
  logging.info('%s\n%s', content, job_saved)
  return {
    'jobs': job_saved,
  }

@deco.json_response
def get_pending_try_patchsets(request):
  limit = int(request.GET.get('limit', '10'))
  if limit > 1000:
    limit = 1000

  master = request.GET.get('master', None)
  encoded_cursor = request.GET.get('cursor', None)
  cursor = None
  if encoded_cursor:
    cursor = datastore_query.Cursor(urlsafe=encoded_cursor)

  def MakeJobDescription(job):
    patchset = job.parent()
    issue = patchset.issue
    owner = issue.owner

    # The job description is the basically the job itself with some extra
    # data from the patchset and issue.
    description = job.to_dict()
    description['name'] = '%d-%d: %s' % (issue.key.id(), patchset.key.id(),
                                         patchset.message)
    description['user'] = owner.nickname()
    description['email'] = owner.email()
    if ('chromium/blink' in issue.base
        or (issue.base.startswith('svn:')
            and issue.base.endswith('blink/trunk'))):
      description['root'] = 'src/third_party/WebKit'
    else:
      description['root'] = 'src'
    description['patchset'] = patchset.key.id()
    description['issue'] = issue.key.id()
    description['baseurl'] = issue.base
    return description

  q = models.TryJobResult.query()
  q = q.filter(models.TryJobResult.result == models.TryJobResult.TRYPENDING)
  if master:
    q = q.filter(models.TryJobResult.master == master)
  q = q.order(models.TryJobResult.timestamp)

  jobs, next_cursor, _ = q.fetch_page(limit, start_cursor=cursor)
  total = len(jobs)
  jobs = [MakeJobDescription(job) for job in jobs if _is_job_valid(job)]
  logging.info('Found %d entries, returned %d' % (total, len(jobs)))
  return {
    'cursor': next_cursor.urlsafe() if next_cursor else '',
    'jobs': jobs
    }
