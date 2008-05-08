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

"""Views for Rietveld.

This requires Django 0.97.pre.
"""


### Imports ###


# Python imports
import os
import cgi
import random
import logging
import binascii

# AppEngine imports
from google.appengine.api import mail
from google.appengine.api import users
from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext.db import djangoforms

# DeadlineExceededError can live in two different places
# TODO(guido): simplify once this is fixed.
try:
  # When deployed
  from google.appengine.runtime import DeadlineExceededError
except ImportError:
  # In the development server
  from google.appengine.runtime.apiproxy_errors import DeadlineExceededError

# Django imports
# TODO(guido): Don't import classes/functions directly.
from django import newforms as forms
from django.http import HttpResponse, HttpResponseRedirect
from django.http import HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import render_to_response

# Local imports
import models
import engine
import library
import patching


### Constants ###


SENDER = 'svncodereview@gmail.com'  # An administrator allowed to send mail

IS_DEV = os.environ['SERVER_SOFTWARE'].startswith('Dev')  # Development server


### Form classes ###


class IssueBaseForm(forms.Form):

  subject = forms.CharField(max_length=100,
                            widget=forms.TextInput(attrs={'size': 60}))
  description = forms.CharField(required=False,
                                max_length=10000,
                                widget=forms.Textarea(attrs={'cols': 60}))
  branch = forms.ChoiceField(required=False, label='SVN base')
  base = forms.CharField(required=False,
                         max_length=1000,
                         widget=forms.TextInput(attrs={'size': 60}))
  reviewers = forms.CharField(required=False,
                              max_length=1000,
                              widget=forms.TextInput(attrs={'size': 60}))

  def set_branch_choices(self, base=None):
    branches = models.Branch.gql('ORDER BY repo, category, name')
    bound_field = self['branch']
    choices = [('', '[See Base]')]
    default = None
    for b in branches:
      pair = (b.key(), '%s - %s - %s' % (b.repo.name, b.category, b.name))
      choices.append(pair)
      if default is None and (base is None or b.url == base):
        default = b.key()
    bound_field.field.choices = choices
    if default is not None:
      self.initial['branch'] = default

  def get_base(self):
    base = self.cleaned_data.get('base')
    if not base:
      key = self.cleaned_data['branch']
      if key:
        branch = models.Branch.get(key)
        if branch is not None:
          base = branch.url
    else:
      try:
        db.Link(base)
      except db.Error:
        self.errors['base'] = ['Invalid base: %s (must be a URL or empty)' %
                               base]
        return None
    if not base:
      self.errors['base'] = ['You must specify a base']
    return base or None


class NewForm(IssueBaseForm):

  data = forms.FileField(required=False)
  url = forms.URLField(required=False,
                       max_length=2083,
                       widget=forms.TextInput(attrs={'size': 60}))


class AddForm(forms.Form):

  message = forms.CharField(max_length=100,
                            widget=forms.TextInput(attrs={'size': 60}))
  data = forms.FileField(required=False)
  url = forms.URLField(required=False,
                       max_length=2083,
                       widget=forms.TextInput(attrs={'size': 60}))


class UploadForm(forms.Form):

  subject = forms.CharField(max_length=100)
  description = forms.CharField(max_length=10000, required=False)
  base = forms.CharField(max_length=2000)
  data = forms.FileField()
  issue = forms.IntegerField(required=False)

  def get_base(self):
    return self.cleaned_data.get('base')


class EditForm(IssueBaseForm):
  pass


class RepoForm(djangoforms.ModelForm):

  class Meta:
    model = models.Repository
    exclude = ['owner']


class BranchForm(djangoforms.ModelForm):

  class Meta:
    model = models.Branch
    exclude = ['owner']


class PublishForm(forms.Form):

  subject = forms.CharField(max_length=100,
                            widget=forms.TextInput(attrs={'size': 60}))
  reviewers = forms.CharField(required=False,
                              max_length=1000,
                              widget=forms.TextInput(attrs={'size': 60}))
  send_mail = forms.BooleanField()
  message = forms.CharField(required=False,
                            max_length=10000,
                            widget=forms.Textarea(attrs={'cols': 60}))


class MiniPublishForm(forms.Form):

  send_mail = forms.BooleanField()
  message = forms.CharField(required=False,
                            max_length=10000,
                            widget=forms.Textarea(attrs={'cols': 60}))


class SettingsForm(forms.Form):

  nickname = forms.CharField(max_length=30)


### Helper functions ###


# Counter displayed (by respond()) below) on every page showing how
# many requests the current incarnation has handled, not counting
# redirects.  Rendered by templates/base.html.
counter = 0

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
  global counter
  counter += 1
  if params is None:
    params = {}
  params['request'] = request
  params['counter'] = counter
  params['user'] = request.user
  params['is_admin'] = request.user_is_admin
  params['is_dev'] = IS_DEV
  params['sign_in'] = users.create_login_url(request.path)
  params['sign_out'] = users.create_logout_url(request.path)
  try:
    return render_to_response(template, params)
  except DeadlineExceededError:
    logging.exception('DeadlineExceededError')
    return HttpResponse('DeadlineExceededError')
  except MemoryError:
    logging.exception('MemoryError')
    return HttpResponse('MemoryError')


def _random_bytes(n):
  """Helper returning a string of random bytes of given length."""
  return ''.join(map(chr, (random.randrange(256) for i in xrange(n))))


### Decorators for request handlers ###


def login_required(func):
  """Decorator that redirects to the login page if you're not logged in."""
  def login_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(users.create_login_url(request.path))
    return func(request, *args, **kwds)
  return login_wrapper


def admin_required(func):
  def admin_wrapper(request, *args, **kwds):
    """Decorator that insists that you're logged in as administratior."""
    if request.user is None:
      return HttpResponseRedirect(users.create_login_url(request.path))
    if not request.user_is_admin:
      return HttpResponseForbidden('You must be admin in for this function')
    return func(request, *args, **kwds)
  return admin_wrapper


def issue_required(func):
  """Decorator that processes the issue_id handler argument."""
  def issue_wrapper(request, issue_id, *args, **kwds):
    issue = models.Issue.get_by_id(int(issue_id))
    if issue is None:
      return HttpResponseNotFound('No issue exists with that id (%s)' %
                                  issue_id)
    request.issue = issue
    return func(request, *args, **kwds)
  return issue_wrapper


def issue_owner_required(func):
  """Decorator that processes the issue_id argument and insists you own it."""
  @issue_required
  @login_required
  def issue_owner_wrapper(request, *args, **kwds):
    if request.issue.owner != request.user:
      return HttpResponseForbidden('You do not own this issue')
    return func(request, *args, **kwds)
  return issue_owner_wrapper


### Request handlers ###


def index(request):
  """/ - Show a list of patches."""
  if request.user is None:
    return all(request)
  else:
    return mine(request)


def all(request):
  """/all - Show a list of up to 30 recent issues."""
  issues = db.GqlQuery('SELECT * FROM Issue ORDER BY modified DESC LIMIT 30')
  return respond(request, 'all.html', {'issues': issues})


@login_required
def mine(request):
  """/mine - Show a list of issues created by the current user."""
  user = request.user
  if 'user' in request.GET:
    name = request.GET['user']
    if '@' in name:
      account = models.Account.get_account_for_email(name)
      if account is not None:
        user = account.user
      else:
        user = users.User(email=name)
    elif name != 'me':
      accounts = models.Account.get_accounts_for_nickname(name)
      if accounts:
        user = accounts[0].user
      else:
        return HttpResponseNotFound('No user found with nickname %r' % name)
  my_issues = list(db.GqlQuery(
      'SELECT * FROM Issue WHERE owner = :1 ORDER BY modified DESC',
      user))
  review_issues = list(db.GqlQuery(
      'SELECT * FROM Issue WHERE reviewers = :1 ORDER BY modified DESC',
      user.email()))
  return respond(request, 'mine.html',
                 {'my_issues': my_issues, 'review_issues': review_issues})


@login_required
def new(request):
  """/new - Upload a new patch set.

  GET shows a blank form, POST processes it.
  """
  if request.method != 'POST':
    form = NewForm()
    form.set_branch_choices()
    return respond(request, 'new.html', {'form': form})

  form = NewForm(request.POST, request.FILES)
  form.set_branch_choices()
  issue = _make_new(request, form)
  if issue is None:
    return respond(request, 'new.html', {'form': form})
  else:
    return HttpResponseRedirect('/%s' % issue.key().id())


def upload(request):
  """/upload - Like new() or add(), but from the upload.py script.

  This generates a text/plain response.
  """
  if request.user is None:
    if IS_DEV:
      request.user = users.User(request.POST.get('user', 'test@example.com'))
    else:
      return HttpResponse('Login required', status=401)
  form = UploadForm(request.POST, request.FILES)
  issue = None
  if form.is_valid():
    issue_id = form.cleaned_data['issue']
    if issue_id:
      action = 'updated'
      issue = models.Issue.get_by_id(issue_id)
      if issue is None:
        form.errors['issue'] = ['No issue exists with that id (%s)' %
                                issue_id]
      else:
        if request.user != issue.owner:
          form.errors['user'] = ['You (%s) don\'t own this issue (%s)' %
                                 (request.user, issue_id)]
          issue = None
        else:
          if not add_patchset_from_form(request, issue, form, 'subject'):
            issue = None
    else:
      action = 'created'
      issue = _make_new(request, form)
  if issue is None:
    msg = 'Issue creation errors:\n%s' % repr(form.errors)
  else:
    msg = ('Issue %s. URL: %s' %
           (action,
            request.build_absolute_uri('/%s' % issue.key().id())))
  return HttpResponse(msg, content_type='text/plain')


class EmptyPatchSet(Exception):
  """Exception used inside _make_new() to break out of the transaction."""


def _make_new(request, form):
  """Helper for new().

  Return a valid Issue, or None.
  """
  if not form.is_valid():
    return None

  data_url = _get_data_url(form)
  if data_url is None:
    return None
  data, url = data_url

  reviewers = _get_reviewers(form)
  if reviewers is None:
    return None

  base = form.get_base()
  if base is None:
    return None

  def txn():
    issue = models.Issue(subject=form.cleaned_data['subject'],
                         description=form.cleaned_data['description'],
                         base=base,
                         reviewers=reviewers,
                         owner=request.user)
    issue.put()

    patchset = models.PatchSet(issue=issue, data=data, url=url,
                               base=base, owner=request.user, parent=issue)
    patchset.put()

    patches = engine.ParsePatchSet(patchset)
    if not patches:
      raise EmptyPatchSet  # Abort the transaction
    db.put(patches)
    return issue

  try:
    return db.run_in_transaction(txn)
  except EmptyPatchSet:
    errkey = url and 'url' or 'data'
    form.errors[errkey] = ['Patch set contains no recognizable patches']
    return None


def _get_data_url(form):
  """Helper for _make_new() above and add() below."""
  cleaned_data = form.cleaned_data

  data = cleaned_data['data']
  url = cleaned_data.get('url')
  if not (data or url):
    form.errors['data'] = ['You must specify a URL or upload a file']
    return None
  if data and url:
    form.errors['data'] = ['You must specify either a URL or upload a file '
                           'but not both']
    return None

  if data is not None:
    data = db.Blob(data.content)
    url = None
  else:
    assert url
    try:
      fetch_result = urlfetch.fetch(url)
    except Exception, err:
      form.errors['url'] = [str(err)]
      return None
    if fetch_result.status_code != 200:
      form.errors['url'] = ['HTTP status code %s' % fetch_result.status_code]
      return None
    data = db.Blob(fetch_result.content)

  return data, url


@issue_owner_required
def add(request):
  """/<issue>/add - Add a new PatchSet to an existing Issue."""
  issue = request.issue
  form = AddForm(request.POST, request.FILES)
  if not add_patchset_from_form(request, issue, form):
    return show(request, issue.key().id(), form)
  return HttpResponseRedirect('/%s' % issue.key().id())


def add_patchset_from_form(request, issue, form, message_key='message'):
  """Helper for add() and upload()."""
  # TODO(guido): use a transaction like in _make_new(); may be share more code?
  if form.is_valid():
    data_url = _get_data_url(form)
  if not form.is_valid():
    return False
  data, url = data_url
  message = form.cleaned_data[message_key]
  patchset = models.PatchSet(issue=issue, message=message, data=data, url=url,
                             base=issue.base, owner=request.user, parent=issue)
  patchset.put()

  patches = engine.ParsePatchSet(patchset)
  if not patches:
    patchset.delete()
    errkey = url and 'url' or 'data'
    form.errors[errkey] = ['Patch set contains no recognizable patches']
    return False
  db.put(patches)
  issue.put()  # To update last modified time
  return True


def _get_reviewers(form):
  """Helper to return the list of reviewers, or None for error."""
  reviewers = []
  raw_reviewers = form.cleaned_data.get('reviewers')
  if raw_reviewers:
    for reviewer in raw_reviewers.split(','):
      reviewer = reviewer.strip()
      if reviewer:
        try:
          reviewer = db.Email(reviewer)
          if reviewer.count('@') != 1:
            raise db.BadValueError('Invalid email address: %s' % reviewer)
          head, tail = reviewer.split('@')
          if '.' not in tail:
            raise db.BadValueError('Invalid email address: %s' % reviewer)
        except db.BadValueError, err:
          form.errors['reviewers'] = [unicode(err)]
          return None
        reviewers.append(reviewer)
  return reviewers



@issue_required
def show(request, form=AddForm()):
  """/<issue> - Show an issue."""
  issue = request.issue
  patchsets = list(issue.patchset_set.order('created'))
  issue.draft_count = 0
  issue.comment_count = 0
  for patchset in patchsets:
    patchset.patches = list(patchset.patch_set.order('filename'))
    patchset.n_comments = 0
    for patch in patchset.patches:
      patchset.n_comments += patch.num_comments
    issue.comment_count += patchset.n_comments
    patchset.n_drafts = 0
    if request.user:
      for patch in patchset.patches:
        patchset.n_drafts += patch.num_drafts
      issue.draft_count += patchset.n_drafts
  last_patchset = first_patch = None
  if patchsets:
    last_patchset = patchsets[-1]
    if last_patchset.patches:
      first_patch = last_patchset.patches[0]
  messages = list(issue.message_set.order('date'))
  return respond(request, 'issue.html',
                 {'issue': issue, 'patchsets': patchsets,
                  'messages': messages, 'form': form,
                  'last_patchset': last_patchset,
                  'first_patch': first_patch})


@issue_owner_required
def edit(request):
  """/<issue>/edit - Edit an issue."""
  issue = request.issue
  base = issue.base

  if request.method != 'POST':
    form = EditForm(initial={'subject': issue.subject,
                             'description': issue.description,
                             'base': base,
                             'reviewers': ', '.join(issue.reviewers)})
    form.set_branch_choices(base)
    return respond(request, 'edit.html', {'issue': issue, 'form': form})

  form = EditForm(request.POST)
  form.set_branch_choices()

  if form.is_valid():
    reviewers = _get_reviewers(form)

  if form.is_valid():
    base = form.get_base()

  if not form.is_valid():
    return respond(request, 'edit.html', {'patchset': patchset, 'form': form})
  cleaned_data = form.cleaned_data

  issue.subject = cleaned_data['subject']
  issue.description = cleaned_data['description']
  base_changed = (issue.base != base)
  issue.base = base
  issue.reviewers = reviewers
  if base_changed:
    for patchset in issue.patchset_set:
      db.run_in_transaction(_delete_cached_contents, list(patchset.patch_set))
  issue.put()

  return HttpResponseRedirect('/%s' % issue.key().id())


def _delete_cached_contents(patch_set):
  """Transactional helper for edit() to delete cached contents."""
  # TODO(guido): No need to do this in a transaction.
  patches = []
  contents = []
  for patch in patch_set:
    try:
      content = patch.content
    except db.Error:
      content = None
    try:
      patched_content = patch.patched_content
    except db.Error:
      patched_content = None
    if content is not None:
      contents.append(content)
    if patched_content is not None:
      contents.append(patched_content)
    patch.content = None
    patch.patched_content = None
    patches.append(patch)
  if contents:
    logging.info("Deleting %d contents", len(contents))
    db.delete(contents)
  if patches:
    logging.info("Updating %d patches", len(patches))
    db.put(patches)


@issue_owner_required
def delete(request):
  """/<issue>/delete - Delete an issue.  There is no way back."""
  issue = request.issue
  tbd = [issue]
  for cls in [models.PatchSet, models.Patch, models.Comment,
              models.Message, models.Content]:
    tbd += cls.gql('WHERE ANCESTOR IS :1', issue)
  db.delete(tbd)
  return HttpResponseRedirect('/mine')


@issue_required
def download(request, patchset_id):
  """/<issue>/download/<patchset> - Download a patch set."""
  patchset = models.PatchSet.get_by_id(int(patchset_id), parent=request.issue)
  if patchset is None:
    return HttpResponseNotFound('No patch set exists with that id (%s)' %
                                patchset_id)
  return HttpResponse(patchset.data, content_type='text/plain')


@issue_required
def patch(request, patchset_id, patch_id):
  """/<issue>/patch/<patchset>/<patch> - View a raw patch."""
  patchset = models.PatchSet.get_by_id(int(patchset_id), parent=request.issue)
  if patchset is None:
    return HttpResponseNotFound('No patch set exists with that id (%s)' %
                                patchset_id)
  patch = models.Patch.get_by_id(int(patch_id), parent=patchset)
  if patch is None:
    return HttpResponseNotFound('No patch exists with that id (%s/%s)' %
                                (patchset_id, patch_id))
  _add_next_prev(patchset, patch)
  return respond(request, 'patch.html',
                 {'patch': patch,
                  'patchset': patchset,
                  'issue': request.issue})


@issue_required
def diff(request, patchset_id, patch_id):
  """/<issue>/diff/<patchset>/<patch> - View a patch as a side-by-side diff."""
  patchset = models.PatchSet.get_by_id(int(patchset_id), parent=request.issue)
  if patchset is None:
    return HttpResponseNotFound('No patch set exists with that id (%s)' %
                                patchset_id)
  patchset.issue = request.issue
  patch = models.Patch.get_by_id(int(patch_id), parent=patchset)
  if patch is None:
    return HttpResponseNotFound('No patch exists with that id (%s/%s)' %
                                (patchset_id, patch_id))
  patch.patchset = patchset

  chunks = patching.ParsePatch(patch.lines, patch.filename)
  if chunks is None:
    return HttpResponseNotFound('Can\'t parse the patch')

  try:
    content = patch.get_content()
  except engine.FetchError, err:
    return HttpResponseNotFound(str(err))

  rows = list(engine.RenderDiffTableRows(request, content.lines,
                                         chunks, patch))
  if rows and rows[-1] is None:
    del rows[-1]
    # Get rid of content, which may be bad
    content.delete()
    patch.content = None
    patch.put()

  _add_next_prev(patchset, patch)
  return respond(request, 'diff.html',
                 {'issue': request.issue, 'patchset': patchset,
                  'patch': patch, 'rows': rows})


@issue_required
def diff2(request, ps_left_id, ps_right_id, patch_id):
  """/<issue>/diff2/... - View the delta between two different patch sets."""
  ps_left = models.PatchSet.get_by_id(int(ps_left_id), parent=request.issue)
  if ps_left is None:
    return HttpResponseNotFound('No patch set exists with that id (%s)' %
                                ps_left_id)
  ps_left.issue = request.issue
  ps_right = models.PatchSet.get_by_id(int(ps_right_id), parent=request.issue)
  if ps_right is None:
    return HttpResponseNotFound('No patch set exists with that id (%s)' %
                                ps_right_id)
  ps_right.issue = request.issue
  patch_right = models.Patch.get_by_id(int(patch_id), parent=ps_right)
  if patch_right is None:
    return HttpResponseNotFound('No patch exists with that id (%s/%s)' %
                                (ps_right_id, patch_id))
  patch_right.patchset = ps_right
  # Now find the corresponding patch in ps_left
  patch_left = models.Patch.gql('WHERE patchset = :1 AND filename = :2',
                                ps_left, patch_right.filename).get()
  if patch_left is None:
    return HttpResponseNotFound(
        "Patch set %s doesn't have a patch with filename %s" %
        (ps_left_id, patch_right.filename))
  try:
    new_content_left = patch_left.get_patched_content()
    new_content_right = patch_right.get_patched_content()
  except engine.FetchError, err:
    return HttpResponseNotFound(str(err))

  rows = engine.RenderDiff2TableRows(request,
                                     new_content_left.lines, patch_left,
                                     new_content_right.lines, patch_right)
  rows = list(rows)
  if rows and rows[-1] is None:
    del rows[-1]

  _add_next_prev(ps_right, patch_right)
  return respond(request, 'diff2.html',
                 {'issue': request.issue,
                  'ps_left': ps_left, 'patch_left': patch_left,
                  'ps_right': ps_right, 'patch_right': patch_right,
                  'rows': rows})


def _add_next_prev(patchset, patch):
  """Helper to add .next and .prev attributes to a patch object."""
  patch.prev = patch.next = None
  patches = list(models.Patch.gql("WHERE patchset = :1 ORDER BY filename",
                                  patchset))
  last = None
  for p in patches:
    if last is not None:
      if p.filename == patch.filename:
        patch.prev = last
      elif last.filename == patch.filename:
        patch.next = p
        break
    last = p


def inline_draft(request):
  """/inline_draft - Ajax handler to submit an in-line draft comment.

  This wraps _inline_draft(); all exceptions are logged and cause an
  abbreviated response indicating something went wrong.
  """
  try:
    return _inline_draft(request)
  except Exception, err:
    logging.exception('Exception in inline_draft processing:')
    # TODO(guido): return some kind of error instead?
    return HttpResponse('<font color="red">Error: %s; please report!</font>' %
                        err.__class__.__name__)


def _inline_draft(request):
  """Helper to submit an in-line draft comment."""
  # TODO(guido): turn asserts marked with XXX into errors
  # Don't use @login_required, since the JS doesn't understand redirects
  assert request.user  # XXX
  snapshot = request.POST.get('snapshot')
  assert snapshot in ('old', 'new'), repr(snapshot)
  left = (snapshot == 'old')
  side = request.POST.get('side')
  assert side in ('a', 'b'), repr(side)  # Display left (a) or right (b)
  issue_id = int(request.POST['issue'])
  issue = models.Issue.get_by_id(issue_id)
  assert issue  # XXX
  patchset_id = int(request.POST.get('patchset') or request.POST[side == 'a' and 'ps_left' or 'ps_right'])
  patchset = models.PatchSet.get_by_id(int(patchset_id), parent=issue)
  assert patchset  # XXX
  patch_id = int(request.POST.get('patch') or request.POST[side == 'a' and 'patch_left' or 'patch_right'])
  patch = models.Patch.get_by_id(int(patch_id), parent=patchset)
  assert patch  # XXX
  text = request.POST.get('text')
  lineno = int(request.POST['lineno'])
  message_id = request.POST.get('message_id')
  comment = None
  if message_id:
    comment = models.Comment.get_by_key_name(message_id, parent=patch)
    if comment is None or not comment.draft or comment.author != request.user:
      comment = None
      message_id = None
  if not message_id:
    # Prefix with 'z' to avoid key names starting with digits.
    message_id = 'z' + binascii.hexlify(_random_bytes(16))

  if not text.rstrip():
    if comment is not None:
      assert comment.draft and comment.author == request.user
      comment.delete()  # Deletion
      comment = None
  else:
    if comment is None:
      comment = models.Comment(key_name=message_id, parent=patch)
    comment.patch = patch
    comment.lineno = lineno
    comment.left = left
    comment.author = request.user
    comment.text = db.Text(text)
    comment.message_id = message_id
    comment.put()
  query = models.Comment.gql(
      'WHERE patch = :patch AND lineno = :lineno AND left = :left '
      'ORDER BY date',
      patch=patch, lineno=lineno, left=left)
  comments = list(c for c in query if not c.draft or c.author == request.user)
  if comment is not None and comment.author is None:
    # Show anonymous draft even though we don't save it
    comments.append(comment)
  if not comments:
    return HttpResponse(' ')
  for c in comments:
    c.complete(patch)
  return render_to_response('inline_comment.html',
                            {'user': request.user,
                             'patch': patch,
                             'patchset': patchset,
                             'issue': issue,
                             'comments': comments,
                             'lineno': lineno,
                             'snapshot': snapshot,
                             'side': side})


PUBLISH_MAIL_TEMPLATE = """Dear %s,

New code review comments by %s have been published.
Please go to %s to read them.

Message:
%s

Details:
%s

Issue Description:
%s

Sincerely,

  Your friendly code review daemon (%s).
"""

@issue_required
@login_required
def publish(request):
  """ /<issue>/publish - Publish draft comments and send mail."""
  issue = request.issue
  if request.user == issue.owner:
    form_class = PublishForm
  else:
    form_class = MiniPublishForm
  if request.method != 'POST':
    form = form_class(initial={'subject': issue.subject,
                               'reviewers': ', '.join(issue.reviewers),
                               'send_mail': True,
                               })
    return respond(request, 'publish.html', {'form': form, 'issue': issue})

  form = form_class(request.POST)
  if form.is_valid():
    reviewers = _get_reviewers(form)
  if not form.is_valid():
    return respond(request, 'publish.html',  {'form': form, 'issue': issue})
  tbd = []  # List of things to put() after all is said and done
  if request.user == issue.owner:
    subject = form.cleaned_data['subject']
    issue.subject = subject
    issue.reviewers = reviewers
  tbd.append(issue)  # To update the last modified time
  message = form.cleaned_data['message'].replace('\r\n', '\n')
  send_mail = form.cleaned_data['send_mail']
  comments = []

  # XXX Should request all drafts for this issue once, now we can.
  for patchset in issue.patchset_set.order('created'):
##     ps_comments = list(models.Comment.gql(
##         'WHERE ANCESTOR IS :1 AND author = :2 AND draft = TRUE',
##         patchset, request.user))
    # XXX Somehow the index broke, do without it
    ps_comments = [c for c in
                   models.Comment.gql('WHERE ANCESTOR IS :1', patchset)
                   if c.draft and c.author == request.user]
    # XXX End
    if ps_comments:
      patches = dict((p.key(), p) for p in patchset.patch_set)
      for p in patches.itervalues():
        p.patchset = patchset
      for c in ps_comments:
        c.draft = False
        # XXX Using internal knowledge about db package: the key for
        # reference property foo is stored as _foo.
        pkey = getattr(c, '_patch', None)
        if pkey in patches:
          patch = patches[pkey]
          c.patch = patch
      tbd.append(ps_comments)
      ps_comments.sort(key=lambda c: (c.patch.filename, not c.left,
                                      c.lineno, c.date))
      comments += ps_comments

  if comments:
    logging.warn('Publishing %d comments', len(comments))
  # Decide who should receive mail
  my_email = db.Email(request.user.email())
  addressees = [db.Email(issue.owner.email())] + issue.reviewers
  if my_email in addressees:
    everyone = addressees[:]
    if len(addressees) > 1:  # Keep it if sending only to yourself
      addressees.remove(my_email)
  else:
    everyone = addressees + [my_email]
  details = _get_draft_details(request, comments)
  text = ((message.strip() + '\n\n' + details.strip())).strip()
  msg = models.Message(issue=issue,
                       subject=issue.subject,
                       sender=my_email,
                       recipients=everyone,
                       text=db.Text(text),
                       parent=issue)
  tbd.append(msg)

  if send_mail:
    url = request.build_absolute_uri('/%s' % issue.key().id())
    addressees_nicknames = ", ".join(library.nickname(addressee, True)
                                     for addressee in addressees)
    my_nickname = library.nickname(request.user, True)
    addressees = ', '.join(addressees)
    description = (issue.description or '').replace('\r\n', '\n')
    home = request.build_absolute_uri('/')
    body = PUBLISH_MAIL_TEMPLATE % (addressees_nicknames, my_nickname,
                                    url, message,
                                    details, description, home)
    logging.warn('Mail: to=%s; cc=%s', addressees, my_email)
    mail.send_mail(sender=SENDER,
                   to=_encode_safely(addressees),
                   subject=_encode_safely('Re: ' + subject),
                   body=_encode_safely(body),
                   cc=_encode_safely(my_email),
                   reply_to=_encode_safely(', '.join(everyone)))

  for obj in tbd:
    db.put(obj)
  return HttpResponseRedirect('/%s' % issue.key().id())


def _encode_safely(s):
  """Helper to turn a unicode string into 8-bit bytes."""
  if isinstance(s, unicode):
    s = s.encode('utf-8')
  return s


def _get_draft_details(request, comments):
  """Helper to display comments with context in the email message."""
  last_key = None
  output = []
  linecache = {}  # Maps (c.patch.filename, c.left) to list of lines
  modified_patches = []
  for c in comments:
    if (c.patch.filename, c.left) != last_key:
      url = request.build_absolute_uri('/%d/diff/%d/%d' %
                                       (request.issue.key().id(),
                                        c.patch.patchset.key().id(),
                                        c.patch.key().id()))
      output.append('\n%s\nFile %s (%s):' % (url, c.patch.filename,
                                             c.left and "left" or "right"))
      last_key = (c.patch.filename, c.left)
      patch = c.patch
      if c.left:
        old_lines = patch.get_content().text.splitlines(True)
        linecache[last_key] = old_lines
      else:
        new_lines = patch.get_patched_content().text.splitlines(True)
        linecache[last_key] = new_lines
    file_lines = linecache.get(last_key, ())
    if 1 <= c.lineno <= len(file_lines):
      context = file_lines[c.lineno - 1].strip()
    else:
      context = ''
    url = request.build_absolute_uri('/%d/diff/%d/%d#%scode%d' %
                                     (request.issue.key().id(),
                                      c.patch.patchset.key().id(),
                                      c.patch.key().id(),
                                      c.left and "old" or "new",
                                      c.lineno))
    output.append('\n%s\nLine %d: %s\n%s'  % (url, c.lineno, context,
                                              c.text.rstrip()))
  if modified_patches:
    db.put(modified_patches)
  return '\n'.join(output)


def repos(request):
  """/repos - Show the list of known Subversion repositories."""
  # Clean up garbage created by buggy edits
  bad_branches = list(models.Branch.gql('WHERE owner = :1', None))
  if bad_branches:
    db.delete(bad_branches)
  branches = models.Branch.gql('ORDER BY repo, category, name')
  return respond(request, 'repos.html', {'branches': branches})


@login_required
def repo_new(request):
  """/repo_new - Create a new Subversion repository record."""
  if request.method != 'POST':
    form = RepoForm()
    return respond(request, 'repo_new.html', {'form': form})
  form = RepoForm(request.POST)
  errors = form.errors
  if not errors:
    try:
      repo = form.save(commit=False)
    except ValueError, err:
      errors['__all__'] = unicode(err)
  if errors:
    return respond(request, 'repo_new.html', {'form': form})
  repo.owner = request.user
  repo.put()
  branch_url = repo.url
  if not branch_url.endswith('/'):
    branch_url += '/'
  branch_url += 'trunk/'
  branch = models.Branch(repo=repo, category='*trunk*', name='Trunk',
                         url=branch_url)
  branch.owner = request.user
  branch.put()
  return HttpResponseRedirect('/repos')


SVN_ROOT = 'http://svn.python.org/view/*checkout*/python/'
BRANCHES = [
    # category, name, url suffix
    ('*trunk*', 'Trunk', 'trunk/'),
    ('branch', '2.5', 'branches/release25-maint/'),
    ('branch', 'py3k', 'branches/py3k/'),
    ]

@admin_required
def repo_init(request):
  """/repo_init - Initialze the list of known Subversion repositories."""
  python = models.Repository.gql("WHERE name = 'Python'").get()
  if python is None:
    python = models.Repository(name='Python', url=SVN_ROOT, owner=request.user)
    python.put()
    pybranches = []
  else:
    pybranches = list(models.Branch.gql('WHERE repo = :1', python))
  for category, name, url in BRANCHES:
    url = python.url + url
    for br in pybranches:
      if (br.category, br.name, br.url) == (category, name, url):
        break
    else:
      br = models.Branch(repo=python, category=category, name=name, url=url,
                         owner=request.user)
      br.put()
  return HttpResponseRedirect('/repos')

@login_required
def branch_new(request, repo_id):
  """/branch_new/<repo> - Add a new Branch to a Repository record."""
  repo = models.Repository.get_by_id(int(repo_id))
  if request.method != 'POST':
    # XXX Use repo.key() so that the default gets picked up
    form = BranchForm(initial={'repo': repo.key(),
                               'url': repo.url,
                               'category': 'branch'})
    return respond(request, 'branch_new.html', {'form': form, 'repo': repo})
  form = BranchForm(request.POST)
  errors = form.errors
  if not errors:
    try:
      branch = form.save(commit=False)
    except ValueError, err:
      errors['__all__'] = unicode(err)
  if errors:
    return respond(request, 'branch_new.html', {'form': form, 'repo': repo})
  branch.owner = request.user
  branch.put()
  return HttpResponseRedirect('/repos')


@login_required
def branch_edit(request, branch_id):
  """/branch_edit/<branch> - Edit a Branch record."""
  branch = models.Branch.get_by_id(int(branch_id))
  if branch.owner != request.user:
    return HttpResponseForbidden('You do not own this branch')
  if request.method != 'POST':
    form = BranchForm(instance=branch)
    return respond(request, 'branch_edit.html',
                   {'branch': branch, 'form': form})
  form = BranchForm(request.POST, instance=branch)
  errors = form.errors
  if not errors:
    try:
      branch = form.save(commit=False)
    except ValueError, err:
      errors['__all__'] = unicode(err)
  if errors:
    return respond(request, 'branch_edit.html',
                   {'branch': branch, 'form': form})
  branch.put()
  return HttpResponseRedirect('/repos')


@login_required
def branch_delete(request, branch_id):
  """/branch_delete/<branch> - Delete a Branch record."""
  branch = models.Branch.get_by_id(int(branch_id))
  if branch.owner != request.user:
    return HttpResponseForbidden('You do not own this branch')
  repo = branch.repo
  branch.delete()
  num_branches = models.Branch.gql('WHERE repo = :1', repo).count()
  if not num_branches:
    # Even if we don't own the repository?  Yes, I think so!  Empty
    # repositories have no representation on screen.
    repo.delete()
  return HttpResponseRedirect('/repos')


### User Profiles ###

@login_required
def settings(request):
  account = models.Account.get_account_for_user(request.user)
  if request.method != 'POST':
    nickname = account.nickname
    form = SettingsForm(initial={'nickname': nickname})
    return respond(request, 'settings.html', {'form': form})
  form = SettingsForm(request.POST)
  if form.is_valid():
    nickname = form.cleaned_data['nickname'].strip()
    if not nickname:
      form.errors['nickname'] = ['Your nickname cannot be empty.']
    elif '@' in nickname:
      form.errors['nickname'] = ['Your nickname cannot contain "@".']
    elif ',' in nickname:
      form.errors['nickname'] = ['Your nickname cannot contain ",".']
    elif nickname != account.nickname:
      accounts = models.Account.get_accounts_for_nickname(nickname)
      if accounts:
        form.errors['nickname'] = ['This nickname is already in use.']
      else:
        account.nickname = nickname
        account.put()
  if not form.is_valid():
    return respond(request, 'settings.html', {'form': form})
  return HttpResponseRedirect('/settings')
