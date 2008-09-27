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

"""Views for Rietveld."""


### Imports ###


# Python imports
import os
import cgi
import random
import re
import logging
import binascii
import datetime
import urllib
import md5
from xml.etree import ElementTree
from cStringIO import StringIO

# AppEngine imports
from google.appengine.api import mail
from google.appengine.api import memcache
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
from django import forms
from django.http import Http404
from django.http import HttpResponse, HttpResponseRedirect
from django.http import HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import render_to_response
import django.template
from django.utils import simplejson

# Local imports
import models
import engine
import library
import patching

# Add our own template library.
_library_name = __name__.rsplit('.', 1)[0] + '.library'
if not django.template.libraries.get(_library_name, None):
  django.template.add_to_builtins(_library_name)


### Constants ###


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
  cc = forms.CharField(required=False,
                       max_length=1000,
                       label = 'CC',
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
  send_mail = forms.BooleanField(required=False, initial=True)


class AddForm(forms.Form):

  message = forms.CharField(max_length=100,
                            widget=forms.TextInput(attrs={'size': 60}))
  data = forms.FileField(required=False)
  url = forms.URLField(required=False,
                       max_length=2083,
                       widget=forms.TextInput(attrs={'size': 60}))
  reviewers = forms.CharField(max_length=1000, required=False,
                              widget=forms.TextInput(attrs={'size': 60}))
  send_mail = forms.BooleanField(required=False, initial=True)


class UploadForm(forms.Form):

  subject = forms.CharField(max_length=100)
  description = forms.CharField(max_length=10000, required=False)
  content_upload = forms.BooleanField(required=False)
  separate_patches = forms.BooleanField(required=False)
  base = forms.CharField(max_length=2000, required=False)
  data = forms.FileField(required=False)
  issue = forms.IntegerField(required=False)
  description = forms.CharField(max_length=10000, required=False)
  reviewers = forms.CharField(max_length=1000, required=False)
  cc = forms.CharField(max_length=1000, required=False)
  send_mail = forms.BooleanField(required=False)

  def clean_base(self):
    base = self.cleaned_data.get('base')
    if not base and not self.cleaned_data.get('content_upload', False):
      raise forms.ValidationError, 'SVN base is required.'
    elif base:
      try:
        db.Link(base)
      except db.BadValueError:
        raise forms.ValidationError, 'Invalid URL'
    return self.cleaned_data.get('base')

  def get_base(self):
    return self.cleaned_data.get('base')


class UploadContentForm(forms.Form):
  filename = forms.CharField(max_length=255)
  status = forms.CharField(required=False, max_length=20)
  checksum = forms.CharField(max_length=32)
  file_too_large = forms.BooleanField(required=False)
  is_binary = forms.BooleanField(required=False)
  is_current = forms.BooleanField(required=False)

  def clean(self):
    # Check presence of 'data'. We cannot use FileField because
    # it disallows empty files.
    super(UploadContentForm, self).clean()
    if not self.files and 'data' not in self.files:
      raise forms.ValidationError, 'No content uploaded.'
    return self.cleaned_data

  def get_uploaded_content(self):
    return self.files['data'].read()


class UploadPatchForm(forms.Form):
  filename = forms.CharField(max_length=255)
  content_upload = forms.BooleanField(required=False)

  def get_uploaded_patch(self):
    return self.files['data'].read()


class EditForm(IssueBaseForm):

  closed = forms.BooleanField(required=False)


class EditLocalBaseForm(forms.Form):
  subject = forms.CharField(max_length=100,
                            widget=forms.TextInput(attrs={'size': 60}))
  description = forms.CharField(required=False,
                                max_length=10000,
                                widget=forms.Textarea(attrs={'cols': 60}))
  reviewers = forms.CharField(required=False,
                              max_length=1000,
                              widget=forms.TextInput(attrs={'size': 60}))
  cc = forms.CharField(required=False,
                       max_length=1000,
                       label = 'CC',
                       widget=forms.TextInput(attrs={'size': 60}))
  closed = forms.BooleanField(required=False)

  def get_base(self):
    return None


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
  cc = forms.CharField(required=False,
                       max_length=1000,
                       label = 'CC',
                       widget=forms.TextInput(attrs={'size': 60}))
  send_mail = forms.BooleanField(required=False)
  message = forms.CharField(required=False,
                            max_length=10000,
                            widget=forms.Textarea(attrs={'cols': 60}))
  message_only = forms.BooleanField(required=False,
                                    widget=forms.HiddenInput())


class MiniPublishForm(forms.Form):

  reviewers = forms.CharField(required=False,
                              max_length=1000,
                              widget=forms.TextInput(attrs={'size': 60}))
  cc = forms.CharField(required=False,
                       max_length=1000,
                       label = 'CC',
                       widget=forms.TextInput(attrs={'size': 60}))
  send_mail = forms.BooleanField(required=False)
  message = forms.CharField(required=False,
                            max_length=10000,
                            widget=forms.Textarea(attrs={'cols': 60}))
  message_only = forms.BooleanField(required=False,
                                    widget=forms.HiddenInput())


FORM_CONTEXT_VALUES = [(x, "%d lines" % x) for x in models.CONTEXT_CHOICES]


class SettingsForm(forms.Form):

  nickname = forms.CharField(max_length=30)
  context = forms.IntegerField(widget=forms.Select(choices=FORM_CONTEXT_VALUES),
                               label='Context')


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
  must_choose_nickname = False
  if request.user is not None:
    account = models.Account.current_user_account
    must_choose_nickname = not account.user_has_selected_nickname()
  params['request'] = request
  params['counter'] = counter
  params['user'] = request.user
  params['is_admin'] = request.user_is_admin
  params['is_dev'] = IS_DEV
  full_path = request.get_full_path().encode('utf-8')
  if request.user is None:
    params['sign_in'] = users.create_login_url(full_path)
  else:
    params['sign_out'] = users.create_logout_url(full_path)
  params['must_choose_nickname'] = must_choose_nickname
  try:
    return render_to_response(template, params)
  except DeadlineExceededError:
    logging.exception('DeadlineExceededError')
    return HttpResponse('DeadlineExceededError')
  except MemoryError:
    logging.exception('MemoryError')
    return HttpResponse('MemoryError')
  except AssertionError:
    logging.exception('AssertionError')
    return HttpResponse('AssertionError')


def _random_bytes(n):
  """Helper returning a string of random bytes of given length."""
  return ''.join(map(chr, (random.randrange(256) for i in xrange(n))))


### Decorators for request handlers ###


def post_required(func):
  """Decorator that returns an error unless request.method == 'POST'."""

  def post_wrapper(request, *args, **kwds):
    if request.method != 'POST':
      return HttpResponse('This requires a POST request.', status=405)
    return func(request, *args, **kwds)

  return post_wrapper


def login_required(func):
  """Decorator that redirects to the login page if you're not logged in."""

  def login_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(
          users.create_login_url(request.get_full_path().encode('utf-8')))
    return func(request, *args, **kwds)

  return login_wrapper


def admin_required(func):
  """Decorator that insists that you're logged in as administratior."""

  def admin_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(
          users.create_login_url(request.get_full_path().encode('utf-8')))
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


def user_key_required(func):
  """Decorator that processes the user handler argument."""

  def user_key_wrapper(request, user_key, *args, **kwds):
    user_key = urllib.unquote(user_key)
    if '@' in user_key:
      request.user_to_show = users.User(user_key)
    else:
      accounts = models.Account.get_accounts_for_nickname(user_key)
      if not accounts:
        logging.info("account not found for nickname %s" % user_key)
        return HttpResponseNotFound('No user found with that key (%s)' %
                                    user_key)
      request.user_to_show = accounts[0].user
    return func(request, *args, **kwds)

  return user_key_wrapper


def issue_owner_required(func):
  """Decorator that processes the issue_id argument and insists you own it."""

  @login_required
  @issue_required
  def issue_owner_wrapper(request, *args, **kwds):
    if request.issue.owner != request.user:
      return HttpResponseForbidden('You do not own this issue')
    return func(request, *args, **kwds)

  return issue_owner_wrapper


def patchset_required(func):
  """Decorator that processes the patchset_id argument."""

  @issue_required
  def patchset_wrapper(request, patchset_id, *args, **kwds):
    patchset = models.PatchSet.get_by_id(int(patchset_id), parent=request.issue)
    if patchset is None:
      return HttpResponseNotFound('No patch set exists with that id (%s)' %
                                  patchset_id)
    patchset.issue = request.issue
    request.patchset = patchset
    return func(request, *args, **kwds)

  return patchset_wrapper


def patch_required(func):
  """Decorator that processes the patch_id argument."""

  @patchset_required
  def patch_wrapper(request, patch_id, *args, **kwds):
    patch = models.Patch.get_by_id(int(patch_id), parent=request.patchset)
    if patch is None:
      return HttpResponseNotFound('No patch exists with that id (%s/%s)' %
                                  (request.patchset.key().id(), patch_id))
    patch.patchset = request.patchset
    request.patch = patch
    return func(request, *args, **kwds)

  return patch_wrapper


def image_required(func):
  """Decorator that processes the image argument.
  
  Attributes set on the request:
   content: a Content entity.
  """

  @patch_required
  def image_wrapper(request, image_type, *args, **kwds):
    content = None
    if image_type == "0":
      content = request.patch.content
    elif image_type == "1":
      content = request.patch.patched_content
    # Other values are erroneous so request.content won't be set.
    if not content or not content.data:
      return HttpResponseRedirect("/static/blank.jpg")
    request.content = content
    return func(request, *args, **kwds)

  return image_wrapper


### Request handlers ###


def index(request):
  """/ - Show a list of patches."""
  if request.user is None:
    return all(request)
  else:
    return mine(request)


DEFAULT_LIMIT = 10


def all(request):
  """/all - Show a list of up to DEFAULT_LIMIT recent issues."""
  offset = request.GET.get('offset')
  if offset:
    try:
      offset = int(offset)
    except:
      offset = 0
    else:
      offset = max(0, offset)
  else:
    offset = 0
  limit = request.GET.get('limit')
  if limit:
    try:
      limit = int(limit)
    except:
      limit = DEFAULT_LIMIT
    else:
      limit = max(1, min(limit, 100))
  else:
    limit = DEFAULT_LIMIT
  query = db.GqlQuery('SELECT * FROM Issue '
                      'WHERE closed = FALSE ORDER BY modified DESC')
  # Fetch one more to see if there should be a 'next' link
  issues = query.fetch(limit+1, offset)
  more = bool(issues[limit:])
  if more:
    del issues[limit:]
  if more:
    next = '/all?offset=%d&limit=%d' % (offset+limit, limit)
  else:
    next = ''
  if offset > 0:
    prev = '/all?offset=%d&limit=%d' % (max(0, offset-limit), limit)
  else:
    prev = ''
  newest = ''
  if offset > limit:
    newest = '/all?limit=%d' % limit

  _optimize_draft_counts(issues)
  return respond(request, 'all.html',
                 {'issues': issues, 'limit': limit,
                  'newest': newest, 'prev': prev, 'next': next,
                  'first': offset+1,
                  'last': len(issues) > 1 and offset+len(issues) or None,
                  })


def _optimize_draft_counts(issues):
  """Force _num_drafts to zero for issues that are known to have no drafts.

  Args:
    issues: list of model.Issue instances.

  This inspects the drafts attribute of the current user's Account
  instance, and forces the draft count to zero of those issues in the
  list that aren't mentioned there.

  If there is no current user, all draft counts are forced to 0.
  """
  account = models.Account.current_user_account
  if account is None:
    issue_ids = None
  else:
    issue_ids = account.drafts
  for issue in issues:
    if issue_ids is None or issue.key().id() not in issue_ids:
      issue._num_drafts = 0


@login_required
def mine(request):
  """/mine - Show a list of issues created by the current user."""
  request.user_to_show = request.user
  return _show_user(request)


@login_required
def starred(request):
  """/starred - Show a list of issues starred by the current user."""
  stars = models.Account.current_user_account.stars
  if not stars:
    issues = []
  else:
    issues = [issue for issue in models.Issue.get_by_id(stars)
                    if issue is not None]
    _optimize_draft_counts(issues)
  return respond(request, 'starred.html', {'issues': issues})


@user_key_required
def show_user(request):
  """/user - Show the user's dashboard"""
  return _show_user(request)


def _show_user(request):
  user = request.user_to_show
  my_issues = list(db.GqlQuery(
      'SELECT * FROM Issue '
      'WHERE closed = FALSE AND owner = :1 ORDER BY modified DESC',
      user))
  review_issues = [issue for issue in db.GqlQuery(
      'SELECT * FROM Issue '
      'WHERE closed = FALSE AND reviewers = :1 ORDER BY modified DESC',
      user.email()) if issue.owner != user]
  closed_issues = list(db.GqlQuery(
      'SELECT * FROM Issue '
      'WHERE closed = TRUE AND modified > :1 AND owner = :2 '
      'ORDER BY modified DESC',
      datetime.datetime.now() - datetime.timedelta(days=7), user))
  _optimize_draft_counts(my_issues + review_issues + closed_issues)
  return respond(request, 'user.html',
                 {'email': user.email(),
                  'my_issues': my_issues,
                  'review_issues': review_issues,
                  'closed_issues': closed_issues,
                  })


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


@post_required
def upload(request):
  """/upload - Like new() or add(), but from the upload.py script.

  This generates a text/plain response.
  """
  if request.user is None:
    if IS_DEV:
      request.user = users.User(request.POST.get('user', 'test@example.com'))
    else:
      return HttpResponse('Login required', status=401)
  # Check against old upload.py usage.
  if request.POST.get('num_parts') > 1:
    return HttpResponse('Upload.py is too old, get the latest version.',
                        content_type='text/plain')
  form = UploadForm(request.POST, request.FILES)
  issue = None
  patchset = None
  if form.is_valid():
    issue_id = form.cleaned_data['issue']
    if issue_id:
      action = 'updated'
      issue = models.Issue.get_by_id(issue_id)
      if issue is None:
        form.errors['issue'] = ['No issue exists with that id (%s)' %
                                issue_id]
      elif issue.local_base and not form.cleaned_data.get('content_upload'):
        form.errors['issue'] = ['Base files upload required for that issue.']
        issue = None
      else:
        if request.user != issue.owner:
          form.errors['user'] = ['You (%s) don\'t own this issue (%s)' %
                                 (request.user, issue_id)]
          issue = None
        else:
          patchset = _add_patchset_from_form(request, issue, form, 'subject',
                                             emails_add_only=True)
          if not patchset:
            issue = None
    else:
      action = 'created'
      issue = _make_new(request, form)
      if issue is not None:
        patchset = issue.patchset
  if issue is None:
    msg = 'Issue creation errors: %s' % repr(form.errors)
  else:
    msg = ('Issue %s. URL: %s' %
           (action,
            request.build_absolute_uri('/%s' % issue.key().id())))
    if (form.cleaned_data.get('content_upload') or
        form.cleaned_data.get('separate_patches')):
      # Extend the response message: 2nd line is patchset id.
      msg +="\n%d" % patchset.key().id()
      if form.cleaned_data.get('content_upload'):
        # Extend the response: additional lines are the expected filenames.
        issue.local_base = True
        issue.put()

        new_content_entities = []
        patches = list(patchset.patch_set)
        for patch in patches:
          content = models.Content(is_uploaded=True, parent=patch)
          new_content_entities.append(content)
        db.put(new_content_entities)

        for patch, content_entity in zip(patches, new_content_entities):
          patch.content = content_entity
          msg += "\n%d %s" % (patch.key().id(), patch.filename)
        db.put(patches)
  return HttpResponse(msg, content_type='text/plain')


@post_required
@patch_required
def upload_content(request):
  """/<issue>/upload_content/<patchset>/<patch> - Upload base file contents.

  Used by upload.py to upload base files."""
  form = UploadContentForm(request.POST, request.FILES)
  if not form.is_valid():
    return HttpResponse('ERROR: Upload content errors:\n%s' % repr(form.errors),
                        content_type='text/plain')
  if request.user is None:
    if IS_DEV:
      request.user = users.User(request.POST.get('user', 'test@example.com'))
    else:
      return HttpResponse('Error: Login required', status=401)
  if request.user != request.issue.owner:
    return HttpResponse('ERROR: You (%s) don\'t own this issue (%s).' %
                        (request.user, request.issue.key().id()))
  patch = request.patch
  patch.status = form.cleaned_data['status']
  patch.is_binary = form.cleaned_data['is_binary']
  patch.put()

  if form.cleaned_data['is_current']:
    if patch.patched_content:
      return HttpResponse('ERROR: Already have current content.')
    content = models.Content(is_uploaded=True, parent=patch)
    content.put()
    patch.patched_content = content
    patch.put()
  else:
    content = patch.content

  if form.cleaned_data['file_too_large']:
    content.file_too_large = True
  else:
    data = form.get_uploaded_content()
    checksum = md5.new(data).hexdigest()
    if checksum != request.POST.get('checksum'):
      content.is_bad = True
      content.put()
      return HttpResponse('ERROR: Checksum mismatch.',
                          content_type='text/plain')
    if patch.is_binary:
      content.data = data
    else:
      content.text = engine.ToText(data)
  content.put()
  return HttpResponse('OK', content_type='text/plain')


@post_required
@patchset_required
def upload_patch(request):
  """/<issue>/upload_patch/<patchset> - Upload patch to patchset.

  Used by upload.py to upload a patch when the diff is too large to upload all
  together.
  """
  if request.user is None:
    if IS_DEV:
      request.user = users.User(request.POST.get('user', 'test@example.com'))
    else:
      return HttpResponse('Error: Login required', status=401)
  if request.user != request.issue.owner:
    return HttpResponse('ERROR: You (%s) don\'t own this issue (%s).' %
                        (request.user, request.issue.key().id()))
  form = UploadPatchForm(request.POST, request.FILES)
  if not form.is_valid():
    return HttpResponse('ERROR: Upload patch errors:\n%s' % repr(form.errors),
                        content_type='text/plain')
  patchset = request.patchset
  if patchset.data:
    return HttpResponse('ERROR: Can\'t upload patches to patchset with data.',
                        content_type='text/plain')
  patch = models.Patch(patchset=patchset,
                       text=engine.ToText(form.get_uploaded_patch()),
                       filename=form.cleaned_data['filename'], parent=patchset)
  patch.put()
  if form.cleaned_data.get('content_upload'):
    content = models.Content(is_uploaded=True, parent=patch)
    content.put()
    patch.content = content
    patch.put()

  msg = 'OK\n' + str(patch.key().id())
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
  data, url, separate_patches = data_url

  reviewers = _get_emails(form, 'reviewers')
  if not form.is_valid() or reviewers is None:
    return None

  cc = _get_emails(form, 'cc')
  if not form.is_valid():
    return None

  base = form.get_base()
  if base is None:
    return None

  def txn():
    issue = models.Issue(subject=form.cleaned_data['subject'],
                         description=form.cleaned_data['description'],
                         base=base,
                         reviewers=reviewers,
                         cc=cc,
                         owner=request.user,
                         n_comments=0)
    issue.put()

    patchset = models.PatchSet(issue=issue, data=data, url=url,
                               owner=request.user, parent=issue)
    patchset.put()
    issue.patchset = patchset

    if not separate_patches:
      patches = engine.ParsePatchSet(patchset)
      if not patches:
        raise EmptyPatchSet  # Abort the transaction
      db.put(patches)
    return issue

  try:
    issue = db.run_in_transaction(txn)
  except EmptyPatchSet:
    errkey = url and 'url' or 'data'
    form.errors[errkey] = ['Patch set contains no recognizable patches']
    return None

  if form.cleaned_data.get('send_mail'):
    msg = _make_message(request, issue, '', '', True)
    msg.put()
  return issue


def _get_data_url(form):
  """Helper for _make_new() above and add() below.

  Args:
    form: Django form object.

  Returns:
    3-tuple (data, url, separate_patches).
      data: the diff content, if available.
      url: the url of the diff, if given.
      separate_patches: True iff the patches will be uploaded separately for
        each file.

  """
  cleaned_data = form.cleaned_data

  data = cleaned_data['data']
  url = cleaned_data.get('url')
  separate_patches = cleaned_data.get('separate_patches')
  if not (data or url or separate_patches):
    form.errors['data'] = ['You must specify a URL or upload a file']
    return None
  if data and url:
    form.errors['data'] = ['You must specify either a URL or upload a file '
                           'but not both']
    return None
  if separate_patches and (data or url):
    form.errors['data'] = ['If the patches will be uploaded separately later, '
                           'you can\'t send some data or a url.']
    return None

  if data is not None:
    data = db.Blob(data.read())
    url = None
  elif url:
    try:
      fetch_result = urlfetch.fetch(url)
    except Exception, err:
      form.errors['url'] = [str(err)]
      return None
    if fetch_result.status_code != 200:
      form.errors['url'] = ['HTTP status code %s' % fetch_result.status_code]
      return None
    data = db.Blob(fetch_result.content)

  return data, url, separate_patches


@post_required
@issue_owner_required
def add(request):
  """/<issue>/add - Add a new PatchSet to an existing Issue."""
  issue = request.issue
  form = AddForm(request.POST, request.FILES)
  if not _add_patchset_from_form(request, issue, form):
    return show(request, issue.key().id(), form)
  return HttpResponseRedirect('/%s' % issue.key().id())


def _add_patchset_from_form(request, issue, form, message_key='message',
                            emails_add_only=False):
  """Helper for add() and upload()."""
  # TODO(guido): use a transaction like in _make_new(); may be share more code?
  if form.is_valid():
    data_url = _get_data_url(form)
  if not form.is_valid():
    return None
  data, url, separate_patches = data_url
  message = form.cleaned_data[message_key]
  patchset = models.PatchSet(issue=issue, message=message, data=data, url=url,
                             owner=request.user, parent=issue)
  patchset.put()

  if not separate_patches:
    patches = engine.ParsePatchSet(patchset)
    if not patches:
      patchset.delete()
      errkey = url and 'url' or 'data'
      form.errors[errkey] = ['Patch set contains no recognizable patches']
      return None
    db.put(patches)

  if emails_add_only:
    emails = _get_emails(form, 'reviewers')
    if not form.is_valid():
      return None
    issue.reviewers += [reviewer for reviewer in emails
                        if reviewer not in issue.reviewers]
    emails = _get_emails(form, 'cc')
    if not form.is_valid():
      return None
    issue.cc += [cc for cc in emails if cc not in issue.cc]
  else:
    issue.reviewers = _get_emails(form, 'reviewers')
    issue.cc = _get_emails(form, 'cc')
  issue.put()

  if form.cleaned_data.get('send_mail'):
    msg = _make_message(request, issue, message, '', True)
    msg.put()
  return patchset


def _get_emails(form, label):
  """Helper to return the list of reviewers, or None for error."""
  emails = []
  raw_emails = form.cleaned_data.get(label)
  if raw_emails:
    for email in raw_emails.split(','):
      email = email.strip()
      if email:
        try:
          if '@' not in email:
            accounts = models.Account.get_accounts_for_nickname(email)
            if len(accounts) != 1:
              raise db.BadValueError('Unknown user: %s' % email)
            db_email = db.Email(accounts[0].user.email().lower())
          elif email.count('@') != 1:
            raise db.BadValueError('Invalid email address: %s' % email)
          else:
            head, tail = email.split('@')
            if '.' not in tail:
              raise db.BadValueError('Invalid email address: %s' % email)
            db_email = db.Email(email.lower())
        except db.BadValueError, err:
          form.errors[label] = [unicode(err)]
          return None
        if db_email not in emails:
          emails.append(db_email)
  return emails


def _get_patchset_info(request):
  """ Returns a list of patchsets for the issue.

  Args:
    request: Django Request object.

  Returns:
    A 2-tuple of (issue, patchsets).
  """
  issue = request.issue
  patchsets = list(issue.patchset_set.order('created'))
  if request.user:
    drafts = list(models.Comment.gql('WHERE ANCESTOR IS :1 AND draft = TRUE'
                                     '  AND author = :2',
                                     issue, request.user))
  else:
    drafts = []
  comments = list(models.Comment.gql('WHERE ANCESTOR IS :1 AND draft = FALSE',
                                     issue))
  issue.draft_count = 0
  issue.comment_count = 0
  for patchset in patchsets:
    patchset.patches = list(patchset.patch_set.order('filename'))
    for patch in patchset.patches:
      patch.patchset = patchset  # Prevent getting these over and over
    patchset.n_comments = 0
    for patch in patchset.patches:
      pkey = patch.key()
      patch._num_comments = sum(c.parent_key() == pkey for c in comments)
      patchset.n_comments += patch.num_comments
    issue.comment_count += patchset.n_comments
    patchset.n_drafts = 0
    if request.user:
      for patch in patchset.patches:
        pkey = patch.key()
        patch._num_drafts = sum(c.parent_key() == pkey for c in drafts)
        patchset.n_drafts += patch.num_drafts
      issue.draft_count += patchset.n_drafts
  return issue, patchsets


@issue_required
def show(request, form=None):
  """/<issue> - Show an issue."""
  issue, patchsets = _get_patchset_info(request)
  if not form:
    form = AddForm(initial={'reviewers': ', '.join(issue.reviewers)})
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
                  'first_patch': first_patch,
                  })


@patchset_required
def patchset(request):
  """/patchset/<key> - Returns patchset information."""
  patchset = request.patchset
  issue, patchsets = _get_patchset_info(request)
  for ps in patchsets:
    if ps.key().id() == patchset.key().id():
      patchset = ps
  return respond(request, 'patchset.html',
                 {'issue': issue,
                  'patchset': patchset,
                  'patchsets': patchsets,
                  })


@issue_owner_required
def edit(request):
  """/<issue>/edit - Edit an issue."""
  issue = request.issue
  base = issue.base

  if issue.local_base:
    form_cls = EditLocalBaseForm
  else:
    form_cls = EditForm

  if request.method != 'POST':
    reviewers = [models.Account.get_nickname_for_email(reviewer,
                                                       default=reviewer)
                 for reviewer in issue.reviewers]
    ccs = [models.Account.get_nickname_for_email(cc, default=cc)
           for cc in issue.cc]
    form = form_cls(initial={'subject': issue.subject,
                             'description': issue.description,
                             'base': base,
                             'reviewers': ', '.join(reviewers),
                             'cc': ', '.join(ccs),
                             'closed': issue.closed,
                             })
    if not issue.local_base:
      form.set_branch_choices(base)
    return respond(request, 'edit.html', {'issue': issue, 'form': form})

  form = form_cls(request.POST)
  if not issue.local_base:
    form.set_branch_choices()

  if form.is_valid():
    reviewers = _get_emails(form, 'reviewers')

  if form.is_valid():
    cc = _get_emails(form, 'cc')

  if form.is_valid() and not issue.local_base:
    base = form.get_base()

  if not form.is_valid():
    return respond(request, 'edit.html', {'issue': issue, 'form': form})
  cleaned_data = form.cleaned_data

  issue.subject = cleaned_data['subject']
  issue.description = cleaned_data['description']
  issue.closed = cleaned_data['closed']
  base_changed = (issue.base != base)
  issue.base = base
  issue.reviewers = reviewers
  issue.cc = cc
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


@post_required
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


@post_required
@issue_required
def close(request):
  """/<issue>/close - Close an issue."""
  if request.issue.owner != request.user:
    if not IS_DEV:
      return HttpResponse('Login required', status=401)
  issue = request.issue
  issue.closed = True
  if request.method == 'POST':
    new_description = request.POST.get('description')
    if new_description:
      issue.description = new_description
  issue.put()
  return HttpResponse('Closed', content_type='text/plain')


@post_required
@issue_required
def mailissue(request):
  """/<issue>/mail - Send mail for an issue."""
  if request.issue.owner != request.user:
    if not IS_DEV:
      return HttpResponse('Login required', status=401)
  issue = request.issue
  msg = _make_message(request, issue, '', '', True)
  msg.put()
  return HttpResponse('OK', content_type='text/plain')


@patchset_required
def download(request):
  """/download/<issue>_<patchset>.diff - Download a patch set."""
  return HttpResponse(request.patchset.data, content_type='text/plain')


@issue_required
def description(request):
  """/<issue>/description - Gets/Sets an issue's description."""
  if request.method != 'POST':
    description = request.issue.description or ""
    return HttpResponse(description, content_type='text/plain')
  if request.issue.owner != request.user:
    if not IS_DEV:
      return HttpResponse('Login required', status=401)
  issue = request.issue
  issue.description = request.POST.get('description')
  issue.put()
  return HttpResponse('')


@patch_required
def patch(request):
  """/<issue>/patch/<patchset>/<patch> - View a raw patch."""
  return patch_helper(request)


def patch_helper(request, nav_type='patch'):
  """Returns a unified diff.

  Args:
    request: Django Request object.
    nav_type: the navigation used in the url (i.e. patch/diff/diff2).  Normally
      the user looks at either unified or side-by-side diffs at one time, going
      through all the files in the same mode.  However, if side-by-side is not
      available for some files, we temporarly switch them to unified view, then
      switch them back when we can.  This way they don't miss any files.

  Returns:
    Whatever respond() returns.
  """
  _add_next_prev(request.patchset, request.patch)
  request.patch.nav_type = nav_type
  parsed_lines = patching.ParsePatchToLines(request.patch.lines)
  if parsed_lines is None:
    return HttpResponseNotFound('Can\'t parse the patch')
  rows = engine.RenderUnifiedTableRows(request, parsed_lines)
  return respond(request, 'patch.html',
                 {'patch': request.patch,
                  'patchset': request.patchset,
                  'rows': rows,
                  'issue': request.issue,
                  })


@image_required
def image(request):
  """/<issue>/content/<patchset>/<patch>/<content> - Return patch's content."""
  return HttpResponse(request.content.data)


@patch_required
def download_patch(request):
  """/download/issue<issue>_<patchset>_<patch>.diff - Download patch."""
  return HttpResponse(request.patch.text, content_type='text/plain')


def _get_context_for_user(request):
  """Returns the context setting for a user.

  The value is validated against models.CONTEXT_CHOICES.
  If an invalid value is found, the value is overwritten with
  engine.DEFAULT_CONTEXT.
  """
  if request.user:
    account = models.Account.current_user_account
    default_context = account.default_context
  else:
    default_context = engine.DEFAULT_CONTEXT
  try:
    context = int(request.GET.get("context", default_context))
  except ValueError:
    context = default_context
  if context not in models.CONTEXT_CHOICES:
    context = engine.DEFAULT_CONTEXT
  return context


@patch_required
def diff(request):
  """/<issue>/diff/<patchset>/<patch> - View a patch as a side-by-side diff"""
  if request.patch.no_base_file:
    # Can't show side-by-side diff since we don't have the base file.  Show the
    # unified diff instead.
    return patch_helper(request, 'diff')

  patchset = request.patchset
  patch = request.patch

  context = _get_context_for_user(request)
  if patch.is_binary:
    rows = None
  else:
    rows = _get_diff_table_rows(request, patch, context)

  _add_next_prev(patchset, patch)
  return respond(request, 'diff.html',
                 {'issue': request.issue,
                  'patchset': patchset,
                  'patch': patch,
                  'rows': rows,
                  'context': context,
                  'context_values': models.CONTEXT_CHOICES,
                  })


def _get_diff_table_rows(request, patch, context):
  """Helper function that returns rendered rows for a patch"""
  chunks = patching.ParsePatchToChunks(patch.lines, patch.filename)
  if chunks is None:
    raise Http404

  try:
    content = request.patch.get_content()
  except engine.FetchError, err:
    raise Http404

  rows = list(engine.RenderDiffTableRows(request, content.lines,
                                         chunks, patch,
                                         context=context))
  if rows and rows[-1] is None:
    del rows[-1]
    # Get rid of content, which may be bad
    if content.is_uploaded and content.text != None:
      # Don't delete uploaded content, otherwise get_content()
      # will fetch it.
      content.is_bad = True
      content.text = None
      content.put()
    else:
      content.delete()
      request.patch.content = None
      request.patch.put()

  return rows


@patch_required
def diff_skipped_lines(request, id_before, id_after, where):
  """/<issue>/diff/<patchset>/<patch> - Returns a fragment of skipped lines"""
  patchset = request.patchset
  patch = request.patch

  # TODO: allow context = None?
  rows = _get_diff_table_rows(request, patch, 10000)
  return _get_skipped_lines_response(rows, id_before, id_after, where)


def _get_skipped_lines_response(rows, id_before, id_after, where):
  """Helper function that creates a Response object for skipped lines"""
  response_rows = []
  id_before = int(id_before)
  id_after = int(id_after)

  if where == "b":
    rows.reverse()

  for row in rows:
    m = re.match('^<tr( name="hook")? id="pair-(?P<rowcount>\d+)">', row)
    if m:
      curr_id = int(m.groupdict().get("rowcount"))
      if curr_id < id_before or curr_id > id_after:
        continue
      if where == "b" and curr_id <= id_after:
        response_rows.append(row)
      elif where == "t" and curr_id >= id_before:
        response_rows.append(row)
      if len(response_rows) >= 10:
        break

  # Create a usable structure for the JS part
  response = []
  dom = ElementTree.parse(StringIO('<div>%s</div>' % "".join(response_rows)))
  for node in dom.getroot().getchildren():
    content = "\n".join([ElementTree.tostring(x) for x in node.getchildren()])
    response.append([node.items(), content])
  return HttpResponse(simplejson.dumps(response))


def _get_diff2_data(request, ps_left_id, ps_right_id, patch_id, context):
  """Helper function that returns objects for diff2 views"""
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
                                     new_content_right.lines, patch_right,
                                     context=context)
  rows = list(rows)
  if rows and rows[-1] is None:
    del rows[-1]

  return dict(new_content_left=new_content_left, patch_left=patch_left,
              new_conent_right=new_content_right, patch_right=patch_right,
              ps_left=ps_left, ps_right=ps_right, rows=rows)


@issue_required
def diff2(request, ps_left_id, ps_right_id, patch_id):
  """/<issue>/diff2/... - View the delta between two different patch sets."""
  context = _get_context_for_user(request)
  data = _get_diff2_data(request, ps_left_id, ps_right_id, patch_id, context)
  if isinstance(data, HttpResponseNotFound):
    return data

  _add_next_prev(data["ps_right"], data["patch_right"])
  return respond(request, 'diff2.html',
                 {'issue': request.issue,
                  'ps_left': data["ps_left"],
                  'patch_left': data["patch_left"],
                  'ps_right': data["ps_right"],
                  'patch_right': data["patch_right"],
                  'rows': data["rows"],
                  'patch_id': patch_id,
                  'context': context,
                  'context_values': models.CONTEXT_CHOICES,
                  })


@issue_required
def diff2_skipped_lines(request, ps_left_id, ps_right_id, patch_id,
                        id_before, id_after, where):
  """/<issue>/diff2/... - Returns a fragment of skipped lines"""
  data = _get_diff2_data(request, ps_left_id, ps_right_id, patch_id, 10000)
  if isinstance(data, HttpResponseNotFound):
    return data
  return _get_skipped_lines_response(data["rows"], id_before, id_after, where)


def _add_next_prev(patchset, patch):
  """Helper to add .next and .prev attributes to a patch object."""
  patch.prev = patch.next = None
  patches = list(models.Patch.gql("WHERE patchset = :1 ORDER BY filename",
                                  patchset))
  patchset.patches = patches  # Required to render the jump to select.
  last = None
  for p in patches:
    if last is not None:
      if p.filename == patch.filename:
        patch.prev = last
      elif last.filename == patch.filename:
        patch.next = p
        break
    last = p


@post_required
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
  # Don't use @login_required, since the JS doesn't understand redirects.
  if not request.user:
    # Don't log this, spammers have started abusing this.
    return HttpResponse('Not logged in')
  snapshot = request.POST.get('snapshot')
  assert snapshot in ('old', 'new'), repr(snapshot)
  left = (snapshot == 'old')
  side = request.POST.get('side')
  assert side in ('a', 'b'), repr(side)  # Display left (a) or right (b)
  issue_id = int(request.POST['issue'])
  issue = models.Issue.get_by_id(issue_id)
  assert issue  # XXX
  patchset_id = int(request.POST.get('patchset') or
                    request.POST[side == 'a' and 'ps_left' or 'ps_right'])
  patchset = models.PatchSet.get_by_id(int(patchset_id), parent=issue)
  assert patchset  # XXX
  patch_id = int(request.POST.get('patch') or
                 request.POST[side == 'a' and 'patch_left' or 'patch_right'])
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
      # Re-query the comment count.
      models.Account.current_user_account.update_drafts(issue)
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
    # The actual count doesn't matter, just that there's at least one.
    models.Account.current_user_account.update_drafts(issue, 1)

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
                             'side': side,
                             })


def _get_affected_files(issue):
  """Helper to return a list of affected files from the latest patchset.

  Args:
    issue: Issue instance.

  Returns:
    2-tuple containing a list of affected files, and the diff contents if it
    is less than 100 lines (otherwise the second item is an empty string).
  """
  files = []
  modified_count = 0
  diff = ''
  patchsets = list(issue.patchset_set.order('created'))
  if len(patchsets):
    patchset = patchsets[-1]
    for patch in patchset.patch_set.order('filename'):
      file_str = ''
      if patch.status:
        file_str += patch.status + ' '
      file_str += patch.filename
      files.append(file_str)
      modified_count += patch.num_lines

    if modified_count and modified_count < 100:
      diff = patchset.data

  return files, diff


def _get_mail_template(issue):
  """Helper to return the template and context for an email.

  If this is the first email for this issue, a template that lists the
  reviewers, description and files is used.
  """
  context = {}
  if issue.message_set.count(1) == 0:
    template = 'mails/review.txt'
    files, patch = _get_affected_files(issue)
    context.update({'files': files, 'patch': patch})
  else:
    template = 'mails/comment.txt'
  return template, context


@login_required
@issue_required
def publish(request):
  """ /<issue>/publish - Publish draft comments and send mail."""
  issue = request.issue
  if request.user == issue.owner:
    form_class = PublishForm
  else:
    form_class = MiniPublishForm
  if request.method != 'POST':
    reviewers = issue.reviewers[:]
    cc = issue.cc[:]
    if request.user != issue.owner and (request.user.email()
                                        not in issue.reviewers):
      reviewers.append(request.user.email())
      if request.user.email() in cc:
        cc.remove(request.user.email())
    reviewers = [models.Account.get_nickname_for_email(reviewer,
                                                       default=reviewer)
                 for reviewer in reviewers]
    ccs = [models.Account.get_nickname_for_email(cc, default=cc) for cc in cc]
    tbd, comments = _get_draft_comments(request, issue, True)
    preview = _get_draft_details(request, comments)
    form = form_class(initial={'subject': issue.subject,
                               'reviewers': ', '.join(reviewers),
                               'cc': ', '.join(ccs),
                               'send_mail': True,
                               })
    return respond(request, 'publish.html', {'form': form,
                                             'issue': issue,
                                             'preview': preview,
                                             })

  form = form_class(request.POST)
  if not form.is_valid():
    return respond(request, 'publish.html', {'form': form, 'issue': issue})
  if request.user == issue.owner:
    issue.subject = form.cleaned_data['subject']
  if form.is_valid() and not form.cleaned_data.get('message_only', False):
    reviewers = _get_emails(form, 'reviewers')
  else:
    reviewers = issue.reviewers
    if request.user != issue.owner and request.user.email() not in reviewers:
      reviewers.append(db.Email(request.user.email()))
  if form.is_valid() and not form.cleaned_data.get('message_only', False):
    cc = _get_emails(form, 'cc')
  else:
    cc = issue.cc
    # The user is in the reviewer list, remove them from CC if they're there.
    if request.user.email() in cc:
      cc.remove(request.user.email())
  if not form.is_valid():
    return respond(request, 'publish.html', {'form': form, 'issue': issue})
  issue.reviewers = reviewers
  issue.cc = cc
  if not form.cleaned_data.get('message_only', False):
    tbd, comments = _get_draft_comments(request, issue)
  else:
    tbd = []
    comments = []
  issue.update_comment_count(len(comments))
  tbd.append(issue)

  if comments:
    logging.warn('Publishing %d comments', len(comments))
  msg = _make_message(request, issue,
                      form.cleaned_data['message'],
                      comments,
                      form.cleaned_data['send_mail'])
  tbd.append(msg)

  for obj in tbd:
    db.put(obj)

  # There are now no comments here (modulo race conditions)
  models.Account.current_user_account.update_drafts(issue, 0)
  return HttpResponseRedirect('/%s' % issue.key().id())


def _encode_safely(s):
  """Helper to turn a unicode string into 8-bit bytes."""
  if isinstance(s, unicode):
    s = s.encode('utf-8')
  return s


def _get_draft_comments(request, issue, preview=False):
  """Helper to return objects to put() and a list of draft comments.

  If preview is True, the list of objects to put() is empty to avoid changes
  to the datastore.

  Args:
    request: Django Request object.
    issue: Issue instance.
    preview: Preview flag (default: False).

  Returns:
    2-tuple (put_objects, comments).
  """
  comments = []
  tbd = []
  # XXX Should request all drafts for this issue once, now we can.
  for patchset in issue.patchset_set.order('created'):
    ps_comments = list(models.Comment.gql(
        'WHERE ANCESTOR IS :1 AND author = :2 AND draft = TRUE',
        patchset, request.user))
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
      if not preview:
        tbd.append(ps_comments)
      ps_comments.sort(key=lambda c: (c.patch.filename, not c.left,
                                      c.lineno, c.date))
      comments += ps_comments
  return tbd, comments


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
      if patch.no_base_file:
        linecache[last_key] = patching.ParsePatchToLines(patch.lines)
      else:
        if c.left:
          old_lines = patch.get_content().text.splitlines(True)
          linecache[last_key] = old_lines
        else:
          new_lines = patch.get_patched_content().text.splitlines(True)
          linecache[last_key] = new_lines
    file_lines = linecache.get(last_key, ())
    context = ''
    if patch.no_base_file:
      for old_line_no, new_line_no, line_text in file_lines:
        if ((c.lineno == old_line_no and c.left) or
            (c.lineno == new_line_no and not c.left)):
          context = line_text.strip()
          break
    else:
      if 1 <= c.lineno <= len(file_lines):
        context = file_lines[c.lineno - 1].strip()
    url = request.build_absolute_uri('/%d/diff/%d/%d#%scode%d' %
                                     (request.issue.key().id(),
                                      c.patch.patchset.key().id(),
                                      c.patch.key().id(),
                                      c.left and "old" or "new",
                                      c.lineno))
    output.append('\n%s\nLine %d: %s\n%s' % (url, c.lineno, context,
                                             c.text.rstrip()))
  if modified_patches:
    db.put(modified_patches)
  return '\n'.join(output)


def _make_message(request, issue, message, comments=None, send_mail=False):
  """Helper to create a Message instance and optionally send an email."""
  template, context = _get_mail_template(issue)
  # Decide who should receive mail
  my_email = db.Email(request.user.email())
  to = [db.Email(issue.owner.email())] + issue.reviewers
  cc = issue.cc[:]
  reply_to = to + cc
  if my_email in to and len(to) > 1:  # send_mail() wants a non-empty to list
    to.remove(my_email)
  if my_email in cc:
    cc.remove(my_email)
  subject = issue.subject
  if issue.message_set.count(1) > 0:
    subject = 'Re: ' + subject
  if comments:
    details = _get_draft_details(request, comments)
  else:
    details = ''
  message = message.replace('\r\n', '\n')
  text = ((message.strip() + '\n\n' + details.strip())).strip()
  msg = models.Message(issue=issue,
                       subject=subject,
                       sender=my_email,
                       recipients=reply_to,
                       text=db.Text(text),
                       parent=issue)

  if send_mail:
    url = request.build_absolute_uri('/%s' % issue.key().id())
    to_nicknames = ', '.join(library.nickname(to_temp, True)
                             for to_temp in to)
    cc_nicknames = ', '.join(library.nickname(cc_temp, True)
                             for cc_temp in cc)
    my_nickname = library.nickname(request.user, True)
    to = ', '.join(to)
    cc = ', '.join(cc)
    reply_to = ', '.join(reply_to)
    description = (issue.description or '').replace('\r\n', '\n')
    home = request.build_absolute_uri('/')
    context.update({'to_nicknames': to_nicknames,
                    'cc_nicknames': cc_nicknames,
                    'my_nickname': my_nickname, 'url': url,
                    'message': message, 'details': details,
                    'description': description, 'home': home,
                    })
    body = django.template.loader.render_to_string(template, context)
    logging.warn('Mail: to=%s; cc=%s', to, cc)
    kwds = {}
    if cc:
      kwds['cc'] = _encode_safely(cc)
    mail.send_mail(sender=my_email,
                   to=_encode_safely(to),
                   subject=_encode_safely(subject),
                   body=_encode_safely(body),
                   reply_to=_encode_safely(reply_to),
                   **kwds)

  return msg


@post_required
@login_required
@issue_required
def star(request):
  account = models.Account.current_user_account
  account.user_has_selected_nickname()  # This will preserve account.fresh.
  if account.stars is None:
    account.stars = []
  id = request.issue.key().id()
  if id not in account.stars:
    account.stars.append(id)
    account.put()
  return respond(request, 'issue_star.html', {'issue': request.issue})


@post_required
@login_required
@issue_required
def unstar(request):
  account = models.Account.current_user_account
  account.user_has_selected_nickname()  # This will preserve account.fresh.
  if account.stars is None:
    account.stars = []
  id = request.issue.key().id()
  if id in account.stars:
    account.stars[:] = [i for i in account.stars if i != id]
    account.put()
  return respond(request, 'issue_star.html', {'issue': request.issue})


### Repositories and Branches ###


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
                               'category': 'branch',
                               })
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


@post_required
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
  account = models.Account.current_user_account
  if request.method != 'POST':
    nickname = account.nickname
    default_context = account.default_context
    form = SettingsForm(initial={'nickname': nickname,
                                 'context': default_context,
                                 })
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
    elif nickname == 'me':
      form.errors['nickname'] = ['Of course, you are what you are. '
                                 'But \'me\' is for everyone.']
    else:
      accounts = models.Account.get_accounts_for_nickname(nickname)
      if nickname != account.nickname and accounts:
        form.errors['nickname'] = ['This nickname is already in use.']
      else:
        account.nickname = nickname
        account.default_context = form.cleaned_data.get("context")
        account.fresh = False
        account.put()
  if not form.is_valid():
    return respond(request, 'settings.html', {'form': form})
  return HttpResponseRedirect('/mine')


@user_key_required
def user_popup(request):
  """/user_popup - Pop up to show the user info."""
  try:
    return _user_popup(request)
  except Exception, err:
    logging.exception('Exception in user_popup processing:')
    return HttpResponse('<font color="red">Error: %s; please report!</font>' %
                        err.__class__.__name__)


def _user_popup(request):
  user = request.user_to_show
  popup_html = memcache.get('user_popup:' + user.email())
  if popup_html is None:
    num_issues_created = db.GqlQuery(
      'SELECT * FROM Issue '
      'WHERE closed = FALSE AND owner = :1',
      user).count()
    num_issues_reviewed = db.GqlQuery(
      'SELECT * FROM Issue '
      'WHERE closed = FALSE AND reviewers = :1',
      user).count()

    user.nickname = models.Account.get_nickname_for_email(user.email())
    popup_html = render_to_response('user_popup.html',
                            {'user': user,
                             'num_issues_created': num_issues_created,
                             'num_issues_reviewed': num_issues_reviewed,
                             })
    # Use time expired cache because the number of issues will change over time
    memcache.add('user_popup:' + user.email(), popup_html, 60)
  return popup_html
