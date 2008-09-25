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
from google.appengine.ext import db
from google.appengine.api import memcache

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
  n_comments = db.IntegerProperty()

  _is_starred = None

  @property
  def is_starred(self):
    """Whether the current user has this issue starred."""
    if self._is_starred is not None:
      return self._is_starred
    account = Account.current_user_account
    self._is_starred = account is not None and self.key().id() in account.stars
    return self._is_starred

  def update_comment_count(self, n):
    """Increment the n_comments property by n.

    If n_comments in None, compute the count through a query.  (This
    is a transitional strategy while the database contains Issues
    created using a previous version of the schema.)
    """
    if self.n_comments is None:
      self.n_comments = self._get_num_comments()
    self.n_comments += n

  @property
  def num_comments(self):
    """The number of non-draft comments for this issue.

    This is almost an alias for self.n_comments, except that if
    n_comments is None, it is computed through a query, and stored,
    using n_comments as a cache.
    """
    if self.n_comments is None:
      self.n_comments = self._get_num_comments()
    return self.n_comments

  def _get_num_comments(self):
    """Helper to compute the number of comments through a query."""
    return gql(Comment,
               'WHERE ANCESTOR IS :1 AND draft = FALSE',
               self).count()

  _num_drafts = None

  @property
  def num_drafts(self):
    """The number of draft comments on this issue for the current user.

    The value is expensive to compute, so it is cached.
    """
    if self._num_drafts is None:
      account = Account.current_user_account
      if account is None:
        self._num_drafts = 0
      else:
        query = gql(Comment,
            'WHERE ANCESTOR IS :1 AND author = :2 AND draft = TRUE',
            self, account.user)
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
  data = db.BlobProperty()
  is_uploaded = db.BooleanProperty(default=False)
  is_bad = db.BooleanProperty(default=False)
  file_too_large = db.BooleanProperty(required=False, default=False)

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
  status = db.StringProperty()  # 'A', 'A  +', 'M', 'D' etc
  text = db.TextProperty()
  content = db.ReferenceProperty(Content)
  patched_content = db.ReferenceProperty(Content, collection_name='patch2_set')
  is_binary = db.BooleanProperty(required=False, default=False)

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
      user = Account.current_user_account
      if user is None:
        self._num_drafts = 0
      else:
        query = gql(Comment,
                    'WHERE patch = :1 AND draft = TRUE AND author = :2',
                    self, account.user)
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
          logging.warn('Patch.get_content: %s', msg)
          raise engine.FetchError(msg)
        if self.content.is_uploaded and self.content.text == None:
          msg = 'Upload in progress.'
          logging.warn('Patch.get_content: %s', msg)
          raise engine.FetchError(msg)
        else:
          return self.content
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
    chunks = patching.ParsePatchToChunks(self.lines, self.filename)
    new_lines = []
    for tag, old, new in patching.PatchChunks(old_lines, chunks):
      new_lines.extend(new)
    text = db.Text(''.join(new_lines))
    patched_content = Content(text=text, parent=self)
    patched_content.put()
    self.patched_content = patched_content
    self.put()
    return patched_content

  @property
  def no_base_file(self):
    """Returns True iff the base file is not available."""
    return self.content and self.content.file_too_large


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
  """Maps a user or email address to a user-selected nickname, and more.

  Nicknames do not have to be unique.

  The default nickname is generated from the email address by
  stripping the first '@' sign and everything after it.  The email
  should not be empty nor should it start with '@' (AssertionError
  error is raised if either of these happens).

  This also holds a list of ids of starred issues.  The expectation
  that you won't have more than a dozen or so starred issues (a few
  hundred in extreme cases) and the memory used up by a list of
  integers of that size is very modest, so this is an efficient
  solution.  (If someone found a use case for having thousands of
  starred issues we'd have to think of a different approach.)
  """

  user = db.UserProperty(required=True)
  email = db.EmailProperty(required=True)  # key == <email>
  nickname = db.StringProperty(required=True)
  default_context = db.IntegerProperty(default=engine.DEFAULT_CONTEXT,
                                       choices=CONTEXT_CHOICES)
  created = db.DateTimeProperty(auto_now_add=True)
  modified = db.DateTimeProperty(auto_now=True)
  stars = db.ListProperty(int)  # Issue ids of all starred issues
  fresh = db.BooleanProperty()

  # Current user's Account.  Updated by middleware.AddUserToRequestMiddleware.
  current_user_account = None

  @classmethod
  def get_account_for_user(cls, user):
    """Get the Account for a user, creating a default one if needed."""
    email = user.email()
    assert email
    key = '<%s>' % email
    # Since usually the account already exists, first try getting it
    # without the transaction implied by get_or_insert().
    account = cls.get_by_key_name(key)
    if account is not None:
      return account
    nickname = user.nickname()
    if '@' in nickname:
      nickname = nickname.split('@', 1)[0]
    assert nickname
    return cls.get_or_insert(key, user=user, email=email, nickname=nickname,
                             fresh=True)

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
  def get_nickname_for_email(cls, email, default=None):
    """Get the nickname for an email address, possibly a default.

    If default is None a generic nickname is computed from the email
    address.

    Args:
      email: email address.
      default: If given and no account is found, returned as the default value.
    Returns:
      Nickname for given email.
    """
    account = cls.get_account_for_email(email)
    if account is not None and account.nickname:
      return account.nickname
    if default is not None:
      return default
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

  def user_has_selected_nickname(self):
    """Return True if the user picked the nickname.

    Normally this returns 'not self.fresh', but if that property is
    None, we assume that if the created and modified timestamp are
    within 2 seconds, the account is fresh (i.e. the user hasn't
    selected a nickname yet).  We then also update self.fresh, so it
    is used as a cache and may even be written back if we're lucky.
    """
    if self.fresh is None:
      delta = self.created - self.modified
      # Simulate delta = abs(delta)
      if delta.days < 0:
        delta = -delta
      self.fresh = (delta.days == 0 and delta.seconds < 2)
    return not self.fresh

  _drafts = None

  @property
  def drafts(self):
    """A list of issue ids that have drafts by this user.

    This is cached in memcache.
    """
    if self._drafts is None:
      if self._initialize_drafts():
        self._save_drafts()
    return self._drafts

  def update_drafts(self, issue, have_drafts=None):
    """Update the user's draft status for this issue.

    Args:
      issue: an Issue instance.
      have_drafts: optional bool forcing the draft status.  By default,
          issue.num_drafts is inspected (which may query the datastore).

    The Account is written to the datastore if necessary.
    """
    dirty = False
    if self._drafts is None:
      dirty = self._initialize_drafts()
    id = issue.key().id()
    if have_drafts is None:
      have_drafts = bool(issue.num_drafts)  # Beware, this may do a query.
    if have_drafts:
      if id not in self._drafts:
        self._drafts.append(id)
        dirty = True
    else:
      if id in self._drafts:
        self._drafts.remove(id)
        dirty = True
    if dirty:
      self._save_drafts()

  def _initialize_drafts(self):
    """Initialize self._drafts from scratch.

    This mostly exists as a schema conversion utility.

    Returns:
      True if the user should call self._save_drafts(), False if not.
    """
    drafts = memcache.get('user_drafts:' + self.email)
    if drafts is not None:
      self._drafts = drafts
      ##logging.info('HIT: %s -> %s', self.email, self._drafts)
      return False
    # We're looking for the Issue key id.  The ancestry of comments goes:
    # Issue -> PatchSet -> Patch -> Comment.
    issue_ids = set(comment.key().parent().parent().parent().id()
                    for comment in gql(Comment,
                                       'WHERE author = :1 AND draft = TRUE',
                                       self.user))
    self._drafts = list(issue_ids)
    ##logging.info('INITIALIZED: %s -> %s', self.email, self._drafts)
    return True

  def _save_drafts(self):
    """Save self._drafts to memcache."""
    ##logging.info('SAVING: %s -> %s', self.email, self._drafts)
    memcache.set('user_drafts:' + self.email, self._drafts, 3600)
