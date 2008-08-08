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

"""App Engine data model (schema) definition for Rietveld."""

# Python imports
import logging
import re

# AppEngine imports
from google.appengine.api import users
from google.appengine.ext import db

# Local imports
import engine
import patching


CONTEXT_CHOICES = (3, 10, 25, 50, 75, 100)


### GQL query cache ###


_query_cache = {}

def gql(cls, clause, *args, **kwds):
  """Return a query object, from the cache if possible.

  Args:
    cls: a db.Model subclass.
    clause: a query clause, e.g. 'WHERE draft = TRUE'.
    *args, **kwds: positional and keyword arguments to be bound to the query.

  Returns:
    A db.GqlQuery instance corresponding to the query with *args and
    **kwds bound to the query.
  """
  query_string = 'SELECT * FROM %s %s' % (cls.kind(), clause)
  query = _query_cache.get(query_string)
  if query is None:
    _query_cache[query_string] = query = db.GqlQuery(query_string)
  query.bind(*args, **kwds)
  return query


### Issues, PatchSets, Patches, Contents, Comments, Messages ###


class Issue(db.Model):
  """The major top-level entity.

  It has one or more PatchSets as its descendants.
  """

  subject = db.StringProperty(required=True)
  description = db.TextProperty()
  base = db.StringProperty()
  local_base = db.BooleanProperty(default=False)
  owner = db.UserProperty(required=True)
  created = db.DateTimeProperty(auto_now_add=True)
  modified = db.DateTimeProperty(auto_now=True)
  reviewers = db.ListProperty(db.Email)
  cc = db.ListProperty(db.Email)
  closed = db.BooleanProperty(default=False)

  _num_comments = None

  @property
  def num_comments(self):
    """The number of (non-draft) comments for this issue.

    The value is expensive to compute, so it is cached.
    """
    if self._num_comments is None:
      self._num_comments = gql(Comment,
          'WHERE ANCESTOR IS :1 AND draft = FALSE',
          self).count()
    return self._num_comments

  _num_drafts = None

  @property
  def num_drafts(self):
    """The number of draft comments on this issue for the current user.

    The value is expensive to compute, so it is cached.
    """
    if self._num_drafts is None:
      user = users.get_current_user()
      if user is None:
        self._num_drafts = 0
      else:
        query = gql(Comment,
            'WHERE ANCESTOR IS :1 AND author = :2 AND draft = TRUE',
            self, user)
        self._num_drafts = query.count()
    return self._num_drafts


class PatchSet(db.Model):
  """A set of patchset uploaded together.

  This is a descendant of an Issue and has Patches as descendants.
  """

  issue = db.ReferenceProperty(Issue)  # == parent
  message = db.StringProperty()
  data = db.BlobProperty()
  url = db.LinkProperty()
  owner = db.UserProperty(required=True)
  created = db.DateTimeProperty(auto_now_add=True)
  modified = db.DateTimeProperty(auto_now=True)


class Message(db.Model):
  """A copy of a message sent out in email.

  This is a descendant of an Issue.
  """

  issue = db.ReferenceProperty(Issue)  # == parent
  subject = db.StringProperty()
  sender = db.EmailProperty()
  recipients = db.ListProperty(db.Email)
  date = db.DateTimeProperty(auto_now_add=True)
  text = db.TextProperty()


class Content(db.Model):
  """The content of a text file.

  This is a descendant of a Patch.
  """

  # parent => Patch
  text = db.TextProperty()
  partial_upload = db.BlobProperty()
  is_uploaded = db.BooleanProperty(default=False)
  is_complete = db.BooleanProperty(default=True)
  is_bad = db.BooleanProperty(default=False)
  num_parts = db.IntegerProperty()
  last_part = db.IntegerProperty()

  @property
  def lines(self):
    """The text split into lines, retaining line endings."""
    if not self.text:
      return []
    return self.text.splitlines(True)


class Patch(db.Model):
  """A single patch, i.e. a set of changes to a single file.

  This is a descendant of a PatchSet.
  """

  patchset = db.ReferenceProperty(PatchSet)  # == parent
  filename = db.StringProperty()
  text = db.TextProperty()
  content = db.ReferenceProperty(Content)
  patched_content = db.ReferenceProperty(Content, collection_name='patch2_set')

  _lines = None

  @property
  def lines(self):
    """The patch split into lines, retaining line endings.

    The value is cached.
    """
    if self._lines is not None:
      return self._lines
    if not self.text:
      lines = []
    else:
      lines = self.text.splitlines(True)
    self._lines = lines
    return lines

  _property_changes = None

  @property
  def property_changes(self):
    """The property changes split into lines.
    
    The value is cached.
    """
    if self._property_changes != None:
      return self._property_changes
    self._property_changes = []
    match = re.search('^Property changes on.*\n'+'_'*67+'$', self.text,
                      re.MULTILINE)
    if match:
      self._property_changes = self.text[match.end():].splitlines()
    return self._property_changes

  @property
  def num_lines(self):
    """The number of lines in this patch."""
    return len(self.lines)

  _num_chunks = None

  @property
  def num_chunks(self):
    """The number of 'chunks' in this patch.

    A chunk is a block of lines starting with '@@'.

    The value is cached.
    """
    if self._num_chunks is None:
      num = 0
      for line in self.lines:
        if line.startswith('@@'):
          num += 1
      self._num_chunks = num
    return self._num_chunks

  _num_comments = None

  @property
  def num_comments(self):
    """The number of non-draft comments for this patch.

    The value is cached.
    """
    if self._num_comments is None:
      self._num_comments = gql(Comment,
                               'WHERE patch = :1 AND draft = FALSE',
                               self).count()
    return self._num_comments

  _num_drafts = None

  @property
  def num_drafts(self):
    """The number of draft comments on this patch for the current user.

    The value is expensive to compute, so it is cached.
    """
    if self._num_drafts is None:
      user = users.get_current_user()
      if user is None:
        self._num_drafts = 0
      else:
        query = gql(Comment,
                    'WHERE patch = :1 AND draft = TRUE AND author = :2',
                    self, user)
        self._num_drafts = query.count()
    return self._num_drafts

  def get_content(self):
    """Get self.content, or fetch it if necessary.

    This is the content of the file to which this patch is relative.

    Returns:
      a Content instance.

    Raises:
      engine.FetchError: If there was a problem fetching it.
    """
    try:
      if self.content is not None:
        if self.content.is_bad:
          msg = 'Bad content. Try to upload again.'
          logging.error(msg)
          raise engine.FetchError(msg)
        if self.content.is_complete:
          return self.content
        else:
          msg = 'Upload in progress.'
          logging.error(msg)
          raise engine.FetchError(msg)
    except db.Error:
      # This may happen when a Content entity was deleted behind our back.
      self.content = None

    content = engine.FetchBase(self.patchset.issue.base, self)
    content.put()
    self.content = content
    self.put()
    return content

  def get_patched_content(self):
    """Get self.patched_content, computing it if necessary.

    This is the content of the file after applying this patch.

    Returns:
      a Content instance.

    Raises:
      engine.FetchError: If there was a problem fetching the old content.
    """
    try:
      if self.patched_content is not None:
        return self.patched_content
    except db.Error:
      # This may happen when a Content entity was deleted behind our back.
      self.patched_content = None

    old_lines = self.get_content().text.splitlines(True)
    logging.info('Creating patched_content for %s', self.filename)
    chunks = patching.ParsePatch(self.lines, self.filename)
    new_lines = []
    for tag, old, new in patching.PatchChunks(old_lines, chunks):
      new_lines.extend(new)
    text = db.Text(''.join(new_lines))
    patched_content = Content(text=text, parent=self)
    patched_content.put()
    self.patched_content = patched_content
    self.put()
    return patched_content

  def get_partial_content(self):
    """Get self.content to append uploaded parts.

    Returns:
      a Context instance.

    Raises:
      engine.FetchError: If there is a problem with the content.
    """
    if not self.content:
      raise engine.FetchError('Content not initialized.')
    if self.content.is_complete:
      raise engine.FetchError('Content is already complete.')
    return self.content


class Comment(db.Model):
  """A Comment for a specific line of a specific file.

  This is a descendant of a Patch.
  """

  patch = db.ReferenceProperty(Patch)  # == parent
  message_id = db.StringProperty()  # == key_name
  author = db.UserProperty()
  date = db.DateTimeProperty(auto_now=True)
  lineno = db.IntegerProperty()
  text = db.TextProperty()
  left = db.BooleanProperty()
  draft = db.BooleanProperty(required=True, default=True)

  def complete(self, patch):
    """Set the shorttext and buckets attributes."""
    # TODO(guido): Turn these into caching proprties instead.
    # TODO(guido): Properly parse the text into quoted and unquoted buckets.
    self.shorttext = self.text.lstrip()[:50].rstrip()
    self.buckets = [Bucket(text=self.text)]


class Bucket(db.Model):
  """A 'Bucket' of text.

  A comment may consist of multiple text buckets, some of which may be
  collapsed by default (when they represent quoted text).

  NOTE: This entity is never written to the database.  See Comment.complete().
  """
  # TODO(guido): Flesh this out.

  text = db.TextProperty()


### Repositories and Branches ###


class Repository(db.Model):
  """A specific Subversion repository."""

  name = db.StringProperty(required=True)
  url = db.LinkProperty(required=True)
  owner = db.UserProperty()

  def __str__(self):
    return self.name


class Branch(db.Model):
  """A trunk, branch, or atag in a specific Subversion repository."""

  repo = db.ReferenceProperty(Repository, required=True)
  category = db.StringProperty(required=True,
                               choices=('*trunk*', 'branch', 'tag'))
  name = db.StringProperty(required=True)
  url = db.LinkProperty(required=True)
  owner = db.UserProperty()


### Accounts ###


class Account(db.Model):
  """Maps a user or email address to a user-selected nickname.

  Nicknames do not have to be unique.

  The default nickname is generated from the email address by
  stripping the first '@' sign and everything after it.  The email
  should not be empty nor should it start with '@' (AssertionError
  error is raised if either of these happens).
  """

  user = db.UserProperty(required=True)
  email = db.EmailProperty(required=True)  # key == <email>
  nickname = db.StringProperty(required=True)
  default_context = db.IntegerProperty(default=engine.DEFAULT_CONTEXT,
                                       choices=CONTEXT_CHOICES)
  created = db.DateTimeProperty(auto_now_add=True)
  modified = db.DateTimeProperty(auto_now=True)

  @classmethod
  def get_account_for_user(cls, user):
    """Get the Account for a user, creating a default one if needed."""
    email = user.email()
    assert email
    key = '<%s>' % email
    nickname = user.nickname()
    if '@' in nickname:
      nickname = nickname.split('@', 1)[0]
    assert nickname
    return cls.get_or_insert(key, user=user, email=email, nickname=nickname)

  @classmethod
  def get_nickname_for_user(cls, user):
    """Get the nickname for a user."""
    return cls.get_account_for_user(user).nickname

  @classmethod
  def get_account_for_email(cls, email):
    """Get the Account for an email address, or return None."""
    assert email
    key = '<%s>' % email
    return cls.get_by_key_name(key)

  @classmethod
  def get_nickname_for_email(cls, email):
    """Get the nickname for an email address, possibly a default."""
    account = cls.get_account_for_email(email)
    if account is not None and account.nickname:
      return account.nickname
    nickname = email
    if '@' in nickname:
      nickname = nickname.split('@', 1)[0]
    assert nickname
    return nickname

  @classmethod
  def get_accounts_for_nickname(cls, nickname):
    """Get the list of Accounts that have this nickname."""
    assert nickname
    assert '@' not in nickname
    return list(gql(cls, 'WHERE nickname = :1', nickname))

  @classmethod
  def get_email_for_nickname(cls, nickname):
    """Turn a nickname into an email address.

    If the nickname is not unique or does not exist, this returns None.
    """
    accounts = cls.get_accounts_for_nickname(nickname)
    if len(accounts) != 1:
      return None
    return accounts[0].email
