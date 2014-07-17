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

import calendar
import datetime
import itertools
import json
import logging
import md5
import os
import re
import sys
import time

from google.appengine.api import memcache
from google.appengine.api import urlfetch
from google.appengine.api.users import User
from google.appengine.ext import db
from google.appengine.ext import ndb

from django.conf import settings

from codereview import auth_utils
from codereview import patching
from codereview import utils
from codereview.exceptions import FetchError


CONTEXT_CHOICES = (3, 10, 25, 50, 75, 100)


### Issues, PatchSets, Patches, Contents, Comments, Messages ###


class Issue(ndb.Model):
  """The major top-level entity.

  It has one or more PatchSets as its descendants.
  """

  subject = ndb.StringProperty(required=True)
  description = ndb.TextProperty()
  project = ndb.StringProperty()
  #: in Subversion - repository path (URL) for files in patch set
  base = ndb.StringProperty()
  repo_guid = ndb.StringProperty()
  owner = auth_utils.AnyAuthUserProperty(auto_current_user_add=True,
                                         required=True)
  created = ndb.DateTimeProperty(auto_now_add=True)
  modified = ndb.DateTimeProperty(auto_now=True)
  reviewers = ndb.StringProperty(repeated=True)
  cc = ndb.StringProperty(repeated=True)
  closed = ndb.BooleanProperty(default=False)
  private = ndb.BooleanProperty(default=False)
  n_comments = ndb.IntegerProperty()

  # NOTE: Use num_messages instead of using n_messages_sent directly.
  n_messages_sent = ndb.IntegerProperty()

  # List of emails that this issue has updates for.
  updates_for = ndb.StringProperty(repeated=True)

  # JSON: {reviewer_email -> [bool|None]}
  reviewer_approval = ndb.TextProperty()

  # JSON: {reviewer_email -> int}
  draft_count_by_user = ndb.TextProperty()

  _is_starred = None
  _has_updates_for_current_user = None
  _original_subject = None

  @property
  def is_starred(self):
    """Whether the current user has this issue starred."""
    if self._is_starred is not None:
      return self._is_starred
    account = Account.current_user_account
    self._is_starred = account is not None and self.key.id() in account.stars
    return self._is_starred

  def user_can_edit(self, user):
    """Returns True if the given user has permission to edit this issue."""
    return user and (user == self.owner or self.is_collaborator(user)
                     or auth_utils.is_current_user_admin())

  @property
  def edit_allowed(self):
    """Whether the current user can edit this issue."""
    return self.user_can_edit(auth_utils.get_current_user())

  def user_can_view(self, user):
    """Returns True if the given user has permission to view this issue."""
    if not self.private:
      return True
    if user is None:
      return False
    email = user.email().lower()
    return (self.user_can_edit(user) or
            email in self.cc or
            email in self.reviewers)

  @property
  def view_allowed(self):
    """Whether the current user can view this issue."""
    return self.user_can_view(auth_utils.get_current_user())

  @property
  def num_messages(self):
    """Get and/or calculate the number of messages sent for this issue."""
    if self.n_messages_sent is None:
      self.calculate_updates_for()
    return self.n_messages_sent

  @num_messages.setter
  def num_messages(self, val):
    """Setter for num_messages."""
    self.n_messages_sent = val

  @property
  def patchsets(self):
    return PatchSet.query(ancestor=self.key).order(Issue.created)

  @property
  def messages(self):
    return Message.query(ancestor=self.key).order(Message.date)

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
    return Comment.query(Comment.draft == False, ancestor=self.key).count()

  _num_drafts = None

  def get_num_drafts(self, user):
    """The number of draft comments on this issue for the user.

    The value is expensive to compute, so it is cached.
    """
    if user is None:
      return 0
    assert isinstance(user, User), 'Expected User, got %r instead.' % user
    if self._num_drafts is None:
      if self.draft_count_by_user is None:
        self.calculate_draft_count_by_user()
      else:
        self._num_drafts = json.loads(self.draft_count_by_user)
    return self._num_drafts.get(user.email(), 0)

  def calculate_draft_count_by_user(self):
    """Computes the number of drafts by user and returns the put future.

    Initializes _num_drafts as a side effect.
    """
    self._num_drafts = {}
    query = Comment.query(Comment.draft == True, ancestor=self.key)
    for comment in query:
      cur = self._num_drafts.setdefault(comment.author.email(), 0)
      self._num_drafts[comment.author.email()] = cur + 1
    self.draft_count_by_user = json.dumps(self._num_drafts)

  @staticmethod
  def _collaborator_emails_from_description(description):
    """Parses a description, returning collaborator email addresses.

    Broken out for unit testing.
    """
    collaborators = []
    for line in description.splitlines():
      m = re.match(
        r'\s*COLLABORATOR\s*='
        r'\s*([a-zA-Z0-9._]+@[a-zA-Z0-9_]+\.[a-zA-Z0-9._]+)\s*',
        line)
      if m:
        collaborators.append(m.group(1))
    return collaborators

  def collaborator_emails(self):
    """Returns a possibly empty list of emails specified in
    COLLABORATOR= lines.

    Note that one COLLABORATOR= lines is required per address.
    """
    if not self.description:
      return []
    return Issue._collaborator_emails_from_description(self.description)

  def is_collaborator(self, user):
    """Returns true if the given user is a collaborator on this issue.

    This is determined by checking if the user's email is listed as a
    collaborator email.
    """
    if not user:
      return False
    return user.email() in self.collaborator_emails()

  @property
  def formatted_reviewers(self):
    """Returns a dict from the reviewer to their approval status."""
    if self.reviewer_approval:
      return json.loads(self.reviewer_approval)
    else:
      # Don't have reviewer_approval calculated, so return all reviewers with
      # no approval status.
      return {r: None for r in self.reviewers}

  @property
  def has_updates(self):
    """Returns True if there have been recent updates on this issue for the
    current user.

    If the current user is an owner, this will return True if there are any
    messages after the last message from the owner.
    If the current user is not the owner, this will return True if there has
    been a message from the owner (but not other reviewers) after the
    last message from the current user."""
    if self._has_updates_for_current_user is None:
      user = auth_utils.get_current_user()
      if not user:
        return False
      self._has_updates_for_current_user = (user.email() in self.updates_for)
    return self._has_updates_for_current_user

  def calculate_updates_for(self, *msgs):
    """Recalculates updates_for, reviewer_approval, and draft_count_by_user,
    factoring in msgs which haven't been sent.

    This only updates this Issue object. You'll still need to put() it to
    the data store for it to take effect.
    """
    updates_for_set = set(self.updates_for)
    approval_dict = {r: None for r in self.reviewers}
    self.num_messages = 0
    old_messages = Message.query(Message.draft == False, ancestor=self.key).order(Message.date)
    for msg in itertools.chain(old_messages, msgs):
      if self._original_subject is None:
        self._original_subject = msg.subject
      self.num_messages += 1
      if msg.sender == self.owner.email():
        updates_for_set.update(self.reviewers, self.cc,
                               self.collaborator_emails())
      else:
        updates_for_set.add(self.owner.email())
        if msg.approval:
          approval_dict[msg.sender] = True
        elif msg.disapproval:
          approval_dict[msg.sender] = False
      updates_for_set.discard(msg.sender)
      self.modified = msg.date
    self.updates_for = updates_for_set
    self.reviewer_approval = json.dumps(approval_dict)

  def calculate_and_save_updates_if_None(self):
    """If this Issue doesn't have a valid updates_for or n_messages_sent,
    calculate them and save them back to the datastore.

    Returns a future for the put() operation or None if this issue is up to
    date."""
    if self.n_messages_sent is None:
      if self.draft_count_by_user is None:
        self.calculate_draft_count_by_user()
      self.calculate_updates_for()
      try:
        # Don't change self.modified when filling cache values. AFAICT, there's
        # no better way...
        self.__class__.modified.auto_now = False
        return self.put_async()
      finally:
        self.__class__.modified.auto_now = True

  def mail_subject(self):
    if self._original_subject is None:
      self.calculate_updates_for()
    if self._original_subject is not None:
      return self._original_subject
    return '%s (issue %d by %s)' % (self.subject, self.key.id(), self.owner.email())

  def get_patchset_info(self, user, patchset_id):
    """Returns a list of patchsets for the issue, and calculates/caches data
    into the |patchset_id|'th one with a variety of non-standard attributes.

    Args:
      user (User) - The user to include drafts for.
      patchset_id (int) - The ID of the PatchSet to calculated info for.
        If this is None, it defaults to the newest PatchSet for this Issue.
    """
    patchsets = list(self.patchsets)
    try:
      if not patchset_id and patchsets:
        patchset_id = patchsets[-1].key.id()

      if user:
        drafts = list(Comment.query(
            Comment.draft == True, Comment.author == user, ancestor=self.key))
      else:
        drafts = []
      comments = list(Comment.query(Comment.draft == False, ancestor=self.key))
      # TODO(andi) Remove draft_count attribute, we already have _num_drafts
      # and it's additional magic.
      self.draft_count = len(drafts)
      for c in drafts:
        c.ps_key = c.patch_key.get().patchset_key
      patchset_id_mapping = {}  # Maps from patchset id to its ordering number.
      for patchset in patchsets:
        patchset_id_mapping[patchset.key.id()] = len(patchset_id_mapping) + 1
        patchset.n_drafts = sum(c.ps_key == patchset.key for c in drafts)
        patchset.patches_cache = None
        patchset.parsed_patches = None
        patchset.total_added = 0
        patchset.total_removed = 0
        if patchset_id == patchset.key.id():
          patchset.patches_cache = list(patchset.patches)
          for patch in patchset.patches_cache:
            pkey = patch.key
            patch._num_comments = sum(c.patch_key == pkey for c in comments)
            if user:
              patch._num_my_comments = sum(
                  c.patch_key == pkey and c.author == user
                  for c in comments)
            else:
              patch._num_my_comments = 0
            patch._num_drafts = sum(c.patch_key == pkey for c in drafts)
            # Reduce memory usage: if this patchset has lots of added/removed
            # files (i.e. > 100) then we'll get MemoryError when rendering the
            # response.  Each Patch entity is using a lot of memory if the
            # files are large, since it holds the entire contents.  Call
            # num_chunks and num_drafts first though since they depend on text.
            # These are 'active' properties and have side-effects when looked
            # up.
            # pylint: disable=W0104
            patch.num_chunks
            patch.num_drafts
            patch.num_added
            patch.num_removed
            patch.text = None
            patch._lines = None
            patch.parsed_deltas = []
            for delta in patch.delta:
              # If delta is not in patchset_id_mapping, it's because of internal
              # corruption.
              if delta in patchset_id_mapping:
                patch.parsed_deltas.append([patchset_id_mapping[delta], delta])
              else:
                logging.error(
                    'Issue %d: %d is missing from %s',
                    self.key.id(), delta, patchset_id_mapping)
            if not patch.is_binary:
              patchset.total_added += patch.num_added
              patchset.total_removed += patch.num_removed
      return patchsets
    finally:
      # Reduce memory usage (see above comment).
      for patchset in patchsets:
        patchset.parsed_patches = None


def _calculate_delta(patch, patchset_id, patchsets):
  """Calculates which files in earlier patchsets this file differs from.

  Args:
    patch: The file to compare.
    patchset_id: The file's patchset's key id.
    patchsets: A list of existing patchsets.

  Returns:
    A list of patchset ids.
  """
  delta = []
  if patch.no_base_file:
    return delta
  for other in patchsets:
    if patchset_id == other.key.id():
      break
    if not hasattr(other, 'parsed_patches'):
      other.parsed_patches = None  # cache variable for already parsed patches
    if other.data or other.parsed_patches:
      # Loading all the Patch entities in every PatchSet takes too long
      # (DeadLineExceeded) and consumes a lot of memory (MemoryError) so instead
      # just parse the patchset's data.  Note we can only do this if the
      # patchset was small enough to fit in the data property.
      if other.parsed_patches is None:
        # Late-import engine because engine imports modules.
        from codereview import engine

        # PatchSet.data is stored as ndb.Blob (str). Try to convert it
        # to unicode so that Python doesn't need to do this conversion
        # when comparing text and patch.text, which is ndb.Text
        # (unicode).
        try:
          other.parsed_patches = engine.SplitPatch(other.data.decode('utf-8'))
        except UnicodeDecodeError:  # Fallback to str - unicode comparison.
          other.parsed_patches = engine.SplitPatch(other.data)
        other.data = None  # Reduce memory usage.
      for filename, text in other.parsed_patches:
        if filename == patch.filename:
          if text != patch.text:
            delta.append(other.key.id())
          break
      else:
        # We could not find the file in the previous patchset. It must
        # be new wrt that patchset.
        delta.append(other.key.id())
    else:
      # other (patchset) is too big to hold all the patches inside itself, so
      # we need to go to the datastore.  Use the index to see if there's a
      # patch against our current file in other.
      query = Patch.query(
          Patch.filename == patch.filename, Patch.patchset_key == other.key)
      other_patches = query.fetch(100)
      if other_patches and len(other_patches) > 1:
        logging.info("Got %s patches with the same filename for a patchset",
                     len(other_patches))
      for op in other_patches:
        if op.text != patch.text:
          delta.append(other.key.id())
          break
      else:
        # We could not find the file in the previous patchset. It must
        # be new wrt that patchset.
        delta.append(other.key.id())

  return delta


class PatchSet(ndb.Model):
  """A set of patchset uploaded together.

  This is a descendant of an Issue and has Patches as descendants.
  """
  # name='issue' is needed for backward compatability with existing data.
  # Note: we could write a mapreduce to rewrite data from the issue field
  # to a new issue_key field, which would allow removal of name='issue',
  # but it would require that migration step on every Rietveld instance.
  issue_key = ndb.KeyProperty(name='issue', kind=Issue)  # == parent
  message = ndb.StringProperty()
  data = ndb.BlobProperty()
  url = ndb.StringProperty()
  created = ndb.DateTimeProperty(auto_now_add=True)
  modified = ndb.DateTimeProperty(auto_now=True)
  n_comments = ndb.IntegerProperty(default=0)

  @property
  def patches(self):
    def reading_order(patch):
      """Sort patches by filename, except .h files before .c files."""
      base, ext = os.path.splitext(patch.filename)
      return (base, ext not in ('.h', '.hxx', '.hpp'), ext)

    patch_list = list(Patch.query(ancestor=self.key))
    return sorted(patch_list, key=reading_order)

  def update_comment_count(self, n):
    """Increment the n_comments property by n."""
    self.n_comments = self.num_comments + n

  @property
  def num_comments(self):
    """The number of non-draft comments for this issue.

    This is almost an alias for self.n_comments, except that if
    n_comments is None, 0 is returned.
    """
    # For older patchsets n_comments is None.
    return self.n_comments or 0

  def calculate_deltas(self):
    patchset_id = self.key.id()
    patchsets = None
    q = Patch.query(Patch.delta_calculated == False, ancestor=self.key)
    for patch in q:
      if patchsets is None:
        # patchsets is retrieved on first iteration because patchsets
        # isn't needed outside the loop at all.
        patchsets = list(self.issue_key.get().patchsets)
      patch.delta = _calculate_delta(patch, patchset_id, patchsets)
      patch.delta_calculated = True
      patch.put()

  def nuke(self):
    ps_id = self.key.id()
    patches = []
    for patchset in self.issue_key.get().patchsets:
      if patchset.created <= self.created:
        continue
      patches.extend(
        p for p in patchset.patches if p.delta_calculated and ps_id in p.delta)

    def _patchset_delete(patches):
      """Transactional helper for delete_patchset.

      Args:
        patches: Patches that have delta against patches of ps_delete.

      """
      patchset_id = self.key.id()
      tbp = []
      for patch in patches:
        patch.delta.remove(patchset_id)
        tbp.append(patch)
      if tbp:
        ndb.put_multi(tbp)
      tbd = [self]
      for cls in [Patch, Comment]:
        tbd.extend(cls.query(ancestor=self.key))
      ndb.delete_multi(entity.key for entity in tbd)
    ndb.transaction(lambda: _patchset_delete(patches))


class Message(ndb.Model):
  """A copy of a message sent out in email.

  This is a descendant of an Issue.
  """
  # name='issue' is needed for backward compatability with existing data.
  issue_key = ndb.KeyProperty(name='issue', kind=Issue)  # == parent
  subject = ndb.StringProperty()
  sender = ndb.StringProperty()
  recipients = ndb.StringProperty(repeated=True)
  date = ndb.DateTimeProperty(auto_now_add=True)
  text = ndb.TextProperty()
  draft = ndb.BooleanProperty(default=False)
  in_reply_to_key = ndb.KeyProperty(name='in_reply_to', kind='Message')
  issue_was_closed = ndb.BooleanProperty(default=False)

  _approval = None
  _disapproval = None

  def find(self, text, owner_allowed=False):
    """Returns True when the message says |text|.

    - Must not be written by the issue owner.
    - Must contain |text| in a line that doesn't start with '>'.
    """
    issue = self.issue_key.get()
    if not owner_allowed and issue.owner.email() == self.sender:
      return False
    return any(
        True for line in self.text.lower().splitlines()
        if not line.strip().startswith('>') and text in line)

  @property
  def approval(self):
    """Is True when the message represents an approval of the review."""
    if self._approval is None:
      self._approval = self.find('lgtm') and not self.disapproval
    return self._approval

  @property
  def disapproval(self):
    """Is True when the message represents a disapproval of the review."""
    if self._disapproval is None:
      self._disapproval = self.find('not lgtm')
    return self._disapproval


class Content(ndb.Model):
  """The content of a text file.

  This is a descendant of a Patch.
  """

  # parent => Patch
  text = ndb.TextProperty()
  data = ndb.BlobProperty()
  # Checksum over text or data depending on the type of this content.
  checksum = ndb.TextProperty()
  is_uploaded = ndb.BooleanProperty(default=False)
  is_bad = ndb.BooleanProperty(default=False)
  file_too_large = ndb.BooleanProperty(default=False)

  @property
  def lines(self):
    """The text split into lines, retaining line endings."""
    if not self.text:
      return []
    return self.text.splitlines(True)


class Patch(ndb.Model):
  """A single patch, i.e. a set of changes to a single file.

  This is a descendant of a PatchSet.
  """

  patchset_key = ndb.KeyProperty(name='patchset', kind=PatchSet)  # == parent
  filename = ndb.StringProperty()
  status = ndb.StringProperty()  # 'A', 'A  +', 'M', 'D' etc
  text = ndb.TextProperty()
  content_key = ndb.KeyProperty(name='content', kind=Content)
  patched_content_key = ndb.KeyProperty(name='patched_content', kind=Content)
  is_binary = ndb.BooleanProperty(default=False)
  # Ids of patchsets that have a different version of this file.
  delta = ndb.IntegerProperty(repeated=True)
  delta_calculated = ndb.BooleanProperty(default=False)

  _lines = None

  @property
  def lines(self):
    """The patch split into lines, retaining line endings.

    The value is cached.
    """
    if self._lines is not None:
      return self._lines

    # Note that self.text has already had newlines normalized on upload.
    # And, any ^L characters are explicitly not treated as breaks.
    bare_lines = self.text.split('\n')
    self._lines = [bare_line + '\n' for bare_line in bare_lines]
    return self._lines

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

  _num_added = None

  @property
  def num_added(self):
    """The number of line additions in this patch.

    The value is cached.
    """
    if self._num_added is None:
      self._num_added = self.count_startswith('+') - 1
    return self._num_added

  _num_removed = None

  @property
  def num_removed(self):
    """The number of line removals in this patch.

    The value is cached.
    """
    if self._num_removed is None:
      self._num_removed = self.count_startswith('-') - 1
    return self._num_removed

  _num_chunks = None

  @property
  def num_chunks(self):
    """The number of 'chunks' in this patch.

    A chunk is a block of lines starting with '@@'.

    The value is cached.
    """
    if self._num_chunks is None:
      self._num_chunks = self.count_startswith('@@')
    return self._num_chunks

  _num_comments = None

  @property
  def num_comments(self):
    """The number of non-draft comments for this patch.

    The value is cached.
    """
    if self._num_comments is None:
      self._num_comments = Comment.query(
          Comment.patch_key == self.key, Comment.draft == False).count()
    return self._num_comments

  _num_my_comments = None

  def num_my_comments(self):
    """The number of non-draft comments for this patch by the logged in user.

    The value is cached.
    """
    if self._num_my_comments is None:
      account = Account.current_user_account
      if account is None:
        self._num_my_comments = 0
      else:
        query = Comment.query(
            Comment.patch_key == self.key, Comment.draft == False,
            Comment.author == account.user)
        self._num_my_comments = query.count()
    return self._num_my_comments

  _num_drafts = None

  @property
  def num_drafts(self):
    """The number of draft comments on this patch for the current user.

    The value is expensive to compute, so it is cached.
    """
    if self._num_drafts is None:
      account = Account.current_user_account
      if account is None:
        self._num_drafts = 0
      else:
        query = Comment.query(
            Comment.patch_key == self.key, Comment.draft == True,
            Comment.author == account.user)
        self._num_drafts = query.count()
    return self._num_drafts

  def count_startswith(self, prefix):
    """Returns the number of lines with the specified prefix."""
    return len([l for l in self.lines if l.startswith(prefix)])

  def get_content(self):
    """Get self.content, or fetch it if necessary.

    This is the content of the file to which this patch is relative.

    Returns:
      a Content instance.

    Raises:
      FetchError: If there was a problem fetching it.
    """
    try:
      if self.content_key is not None:
        content = self.content_key.get()
        if content.is_bad:
          msg = 'Bad content. Try to upload again.'
          logging.warn('Patch.get_content: %s', msg)
          raise FetchError(msg)
        if content.is_uploaded and content.text == None:
          msg = 'Upload in progress.'
          logging.warn('Patch.get_content: %s', msg)
          raise FetchError(msg)
        else:
          return content
    except db.Error:
      # This may happen when a Content entity was deleted behind our back.
      self.content_key = None

    content = self.fetch_base()
    content.put()
    self.content_key = content.key
    self.put()
    return content

  def get_patched_content(self):
    """Get this patch's patched_content, computing it if necessary.

    This is the content of the file after applying this patch.

    Returns:
      a Content instance.

    Raises:
      FetchError: If there was a problem fetching the old content.
    """
    try:
      if self.patched_content_key is not None:
        return self.patched_content_key.get()
    except db.Error:
      # This may happen when a Content entity was deleted behind our back.
      self.patched_content_key = None

    old_lines = self.get_content().text.splitlines(True)
    logging.info('Creating patched_content for %s', self.filename)
    chunks = patching.ParsePatchToChunks(self.lines, self.filename)
    new_lines = []
    for _, _, new in patching.PatchChunks(old_lines, chunks):
      new_lines.extend(new)
    text = ''.join(new_lines)
    patched_content = Content(text=text, parent=self.key)
    patched_content.put()
    self.patched_content_key = patched_content.key
    self.put()
    return patched_content

  @property
  def no_base_file(self):
    """Returns True iff the base file is not available."""
    return self.content_key and self.content_key.get().file_too_large

  def fetch_base(self):
    """Fetch base file for the patch.

    Returns:
      A models.Content instance.

    Raises:
      FetchError: For any kind of problem fetching the content.
    """
    rev = patching.ParseRevision(self.lines)
    if rev is not None:
      if rev == 0:
        # rev=0 means it's a new file.
        return Content(text=u'', parent=self.key)

    # AppEngine can only fetch URLs that db.Link() thinks are OK,
    # so try converting to a db.Link() here.
    issue = self.patchset_key.get().issue_key.get()
    try:
      base = db.Link(issue.base)
    except db.BadValueError:
      msg = 'Invalid base URL for fetching: %s' % issue.base
      logging.warn(msg)
      raise FetchError(msg)

    url = utils.make_url(base, self.filename, rev)
    logging.info('Fetching %s', url)
    try:
      result = urlfetch.fetch(url)
    except urlfetch.Error, err:
      msg = 'Error fetching %s: %s: %s' % (url, err.__class__.__name__, err)
      logging.warn('FetchBase: %s', msg)
      raise FetchError(msg)
    if result.status_code != 200:
      msg = 'Error fetching %s: HTTP status %s' % (url, result.status_code)
      logging.warn('FetchBase: %s', msg)
      raise FetchError(msg)
    return Content(text=utils.to_dbtext(utils.unify_linebreaks(result.content)),
                   parent=self.key)



class Comment(ndb.Model):
  """A Comment for a specific line of a specific file.

  This is a descendant of a Patch.
  """

  patch_key = ndb.KeyProperty(name='patch', kind=Patch)  # == parent
  message_id = ndb.StringProperty()  # == key_name
  author = auth_utils.AnyAuthUserProperty(auto_current_user_add=True)
  date = ndb.DateTimeProperty(auto_now=True)
  lineno = ndb.IntegerProperty()
  text = ndb.TextProperty()
  left = ndb.BooleanProperty()
  draft = ndb.BooleanProperty(required=True, default=True)

  buckets = None
  shorttext = None

  def complete(self):
    """Set the shorttext and buckets attributes."""
    # TODO(guido): Turn these into caching proprties instead.

    # The strategy for buckets is that we want groups of lines that
    # start with > to be quoted (and not displayed by
    # default). Whitespace-only lines are not considered either quoted
    # or not quoted. Same goes for lines that go like "On ... user
    # wrote:".
    cur_bucket = []
    quoted = None
    self.buckets = []

    def _Append():
      if cur_bucket:
        self.buckets.append(Bucket(text="\n".join(cur_bucket),
                                   quoted=bool(quoted)))

    lines = self.text.splitlines()
    for line in lines:
      if line.startswith("On ") and line.endswith(":"):
        pass
      elif line.startswith(">"):
        if quoted is False:
          _Append()
          cur_bucket = []
        quoted = True
      elif line.strip():
        if quoted is True:
          _Append()
          cur_bucket = []
        quoted = False
      cur_bucket.append(line)

    _Append()

    self.shorttext = self.text.lstrip()[:50].rstrip()
    # Grab the first 50 chars from the first non-quoted bucket
    for bucket in self.buckets:
      if not bucket.quoted:
        self.shorttext = bucket.text.lstrip()[:50].rstrip()
        break


class Bucket(ndb.Model):
  """A 'Bucket' of text.

  A comment may consist of multiple text buckets, some of which may be
  collapsed by default (when they represent quoted text).

  NOTE: This entity is never written to the database.  See Comment.complete().
  """
  # TODO(guido): Flesh this out.

  text = ndb.TextProperty()
  quoted = ndb.BooleanProperty()


### Repositories and Branches ###


class Repository(ndb.Model):
  """A specific Subversion repository."""

  name = ndb.StringProperty(required=True)
  url = ndb.StringProperty(required=True)
  owner = auth_utils.AnyAuthUserProperty(auto_current_user_add=True)
  guid = ndb.StringProperty()  # global unique repository id

  def __str__(self):
    return self.name


BRANCH_CATEGORY_CHOICES = ('*trunk*', 'branch', 'tag')

class Branch(ndb.Model):
  """A trunk, branch, or a tag in a specific Subversion repository."""

  repo_key = ndb.KeyProperty(name='repo', kind=Repository, required=True)
  # Cache repo.name as repo_name, to speed up set_branch_choices()
  # in views.IssueBaseForm.
  repo_name = ndb.StringProperty()
  category = ndb.StringProperty(required=True, choices=BRANCH_CATEGORY_CHOICES)
  name = ndb.StringProperty(required=True)
  url = ndb.StringProperty(required=True)
  owner = auth_utils.AnyAuthUserProperty(auto_current_user_add=True)


### Accounts ###


class Account(ndb.Model):
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

  user = auth_utils.AnyAuthUserProperty(auto_current_user_add=True,
                                        required=True)
  email = ndb.StringProperty(required=True)  # key == <email>
  nickname = ndb.StringProperty(required=True)
  default_context = ndb.IntegerProperty(default=settings.DEFAULT_CONTEXT,
                                        choices=CONTEXT_CHOICES)
  default_column_width = ndb.IntegerProperty(
      default=settings.DEFAULT_COLUMN_WIDTH)
  created = ndb.DateTimeProperty(auto_now_add=True)
  modified = ndb.DateTimeProperty(auto_now=True)
  stars = ndb.IntegerProperty(repeated=True)  # Issue ids of all starred issues
  fresh = ndb.BooleanProperty()
  notify_by_email = ndb.BooleanProperty(default=True)
  notify_by_chat = ndb.BooleanProperty(default=False)
  # Spammer; only blocks sending messages, not uploading issues.
  blocked = ndb.BooleanProperty(default=False)

  # Current user's Account.  Updated by middleware.AddUserToRequestMiddleware.
  current_user_account = None

  lower_email = ndb.ComputedProperty(lambda self: self.email.lower())
  lower_nickname = ndb.ComputedProperty(lambda self: self.nickname.lower())
  xsrf_secret = ndb.BlobProperty()

  @classmethod
  def get_id_for_email(cls, email):
    return '<%s>' % email

  @classmethod
  def get_account_for_user(cls, user):
    """Get the Account for a user, creating a default one if needed."""
    email = user.email()
    assert email
    id_str = cls.get_id_for_email(email)
    # Since usually the account already exists, first try getting it
    # without the transaction implied by get_or_insert().
    account = cls.get_by_id(id_str)
    if account is not None:
      return account
    nickname = cls.create_nickname_for_user(user)
    return cls.get_or_insert(
      id_str, user=user, email=email, nickname=nickname, fresh=True)

  @classmethod
  def create_nickname_for_user(cls, user):
    """Returns a unique nickname for a user."""
    name = nickname = user.email().split('@', 1)[0]
    next_char = chr(ord(nickname[0].lower())+1)
    existing_nicks = [
      account.lower_nickname for account in cls.query(
          cls.lower_nickname >= nickname.lower(),
          cls.lower_nickname < next_char)]
    suffix = 0
    while nickname.lower() in existing_nicks:
      suffix += 1
      nickname = '%s%d' % (name, suffix)
    return nickname

  @classmethod
  def get_nickname_for_user(cls, user):
    """Get the nickname for a user."""
    return cls.get_account_for_user(user).nickname

  @classmethod
  def get_account_for_email(cls, email):
    """Get the Account for an email address, or return None."""
    assert email
    id_str = '<%s>' % email
    return cls.get_by_id(id_str)

  @classmethod
  def get_accounts_for_emails(cls, emails):
    """Get the Accounts for each of a list of email addresses."""
    keys = [ndb.Key(cls, '<%s>' % email) for email in emails]
    return ndb.get_multi(keys)

  @classmethod
  def get_multiple_accounts_by_email(cls, emails):
    """Get multiple accounts.  Returns a dict by email."""
    results = {}
    keys = []
    for email in emails:
      if cls.current_user_account and email == cls.current_user_account.email:
        results[email] = cls.current_user_account
      else:
        keys.append(ndb.Key(cls,'<%s>' % email))
    if keys:
      accounts = ndb.get_multi(keys)
      for account in accounts:
        if account is not None:
          results[account.email] = account
    return results

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
    return email.replace('@', '_')

  @classmethod
  def get_account_for_nickname(cls, nickname):
    """Get the list of Accounts that have this nickname."""
    assert nickname
    assert '@' not in nickname
    return cls.query(cls.lower_nickname == nickname.lower()).get()

  @classmethod
  def get_email_for_nickname(cls, nickname):
    """Turn a nickname into an email address.

    If the nickname is not unique or does not exist, this returns None.
    """
    account = cls.get_account_for_nickname(nickname)
    if account is None:
      return None
    return account.email

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
    keyid = issue.key.id()
    if have_drafts is None:
      # Beware, this may do a query.
      have_drafts = bool(issue.get_num_drafts(self.user))
    if have_drafts:
      if keyid not in self._drafts:
        self._drafts.append(keyid)
        dirty = True
    else:
      if keyid in self._drafts:
        self._drafts.remove(keyid)
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
    draft_query = Comment.query(
        Comment.author == self.user, Comment.draft == True)
    issue_ids = set(comment.key.parent().parent().parent().id()
                    for comment in draft_query)
    self._drafts = list(issue_ids)
    ##logging.info('INITIALIZED: %s -> %s', self.email, self._drafts)
    return True

  def _save_drafts(self):
    """Save self._drafts to memcache."""
    ##logging.info('SAVING: %s -> %s', self.email, self._drafts)
    memcache.set('user_drafts:' + self.email, self._drafts, 3600)

  def get_xsrf_token(self, offset=0):
    """Return an XSRF token for the current user."""
    # This code assumes that
    # self.user.email() == auth_utils.get_current_user().email()
    current_user = auth_utils.get_current_user()
    if self.user.user_id() != current_user.user_id():
      # Mainly for Google Account plus conversion.
      logging.info('Updating user_id for %s from %s to %s' % (
        self.user.email(), self.user.user_id(), current_user.user_id()))
      self.user = current_user
      self.put()
    if not self.xsrf_secret:
      self.xsrf_secret = os.urandom(8)
      self.put()
    m = md5.new(self.xsrf_secret)
    email_str = self.lower_email
    if isinstance(email_str, unicode):
      email_str = email_str.encode('utf-8')
    m.update(self.lower_email)
    when = int(time.time()) // 3600 + offset
    m.update(str(when))
    return m.hexdigest()


### Statistics ###


def compute_score(stats):
  """Calculates the score used for the leaderboard.

  If this function is changed, every AccountStats* must be stored again to
  update the score. Lower, the better.

  If this function is updated, also update the legend in
  templates/leaderboard.html.
  """
  score = stats.median_latency
  if score is None:
    return AccountStatsBase.NULL_SCORE
  # - Penalize people who do not respond to their reviews.
  # - People without any lgtm have a bonus +100 score downgrade.
  value = float(score) / stats.nb_reviewed / stats.percent_reviewed
  if not stats.nb_lgtmed:
    value += 100
  return value


class AccountStatsBase(ndb.Model):
  """Base class for Statistics for a single user covering a specific time span.

  Parent is always the corresponding Account.

  There's 3 types of entity types:
  1. Single day summary. AccountStatsDay. Key name is 'YYYY-MM-DD'.
  2. Single month summary. AccountStatsMulti. Key name is 'YYYY-MM'.
  3. 'XX last days' rolling summary. AccountStatsMulti. Key name is the string
     'XX'.

  The statistics encompass all the reviews WHERE THE INITIAL EMAIL WAS SENT IN
  THE DAY. This is important, it's not 'when the issue was created' neither when
  the reviewer woke up. This means finally reviewing a week old CL will worsen
  your score of last week. This could create a bad incentive, but if you punted
  on a review for a week, the author already hates you anyway.

  WARNING: entities can be updated several days after the day they represent, as
  stated in the previous paragraph.

  CLs where no message was ever sent are not considered, since the date is
  pinned on the first message.

  Users that never created an Issue are not considered. See
  views.figure_out_real_accounts().

  In each case, the entity won't exist if the user had no activity, so the
  number of entities scales linearly with the activty going on. More
  specifically for the rolling summary, the entity will only exist if the user
  had activity in the past XX days, as it will be deleted otherwise on the next
  cron job run.

  This entity is written by a cron job once per day per account that had
  activity, so it doesn't need to be updated in a transaction, reducing the
  strain on the datastore. By precomputing the rolling summary, it makes
  displaying the leaderboard seamless performance-wise.
  """
  # These values are types of review where no latency can be calculated:
  # - NORMAL (1): A normal code review.
  # - IGNORED (2): The reviewer hasn't reviewed yet.
  # - DRIVE_BY (3): The reviewer sent a comment while not being on the reviewer
  #                 list before commenting.
  # - NOT_REQUESTED (4): A reviewer commented on an Issue before the author
  #                      published a request for review, so no latency can be
  #                      calculated.
  # - OUTGOING (5): Set for the issue author so he can track how many CLs he
  #                 sent.
  NORMAL, IGNORED, DRIVE_BY, NOT_REQUESTED, OUTGOING = range(1, 6)
  REVIEW_TYPES = [
    None,
    'normal',
    'ignored',
    'drive-by',
    'not requested',
    'outgoing',
  ]

  # Store this value instead of None when the score would be None. Must be a
  # float.
  NULL_SCORE = sys.float_info.max

  # Saved so incomplete cronjob/taskqueue execution can be safely recovered.
  modified = ndb.DateTimeProperty(auto_now=True)

  # Issues. The actual issues considered. Must be non-empty.
  issues = ndb.IntegerProperty(repeated=True)
  # Latencies. List of "request to review" latencies in seconds. Must be in the
  # same order than issues. Issues not reviewed are to be set to < 0.
  latencies = ndb.IntegerProperty(repeated=True)
  # Number of LGTMs for each issue in .issues.
  lgtms = ndb.IntegerProperty(repeated=True)
  # Type of review. Must be one of NORMAL, IGNORED, NOT_REQUESTED, OUTGOING.
  review_types = ndb.IntegerProperty(repeated=True)

  # Computed properties.

  # The same value as .key.id(). Used to do a quick search for every
  # instances for a specific day, month or rolling summary for the leaderboard.
  name = ndb.ComputedProperty(lambda x: x.key.id())
  # Used for the leaderboard. Do not use ComputeProperty() so
  # task_refresh_all_stats_score can determine if the entity needs to be saved
  # again or not.
  score = ndb.FloatProperty(default=NULL_SCORE)

  @property
  def nb_reviewed(self):
    """Total reviews requests where the user replied where a latency can be
    calculated.
    """
    return sum(
        self.review_types[i] != self.OUTGOING and self.latencies[i] >= 0
        for i in xrange(len(self.issues)))

  @property
  def nb_ignored(self):
    """Number of issues the user didn't review yet but should."""
    return sum(r == self.IGNORED for r in self.review_types)

  @property
  def nb_issues(self):
    """Number of issues either reviewed or ignored excluding outgoing issues."""
    return sum(r != self.OUTGOING for r in self.review_types)

  @property
  def nb_lgtmed(self):
    """Number of issues LGTMed."""
    return sum(
        self.review_types[i] != self.OUTGOING and self.lgtms[i] > 0
        for i in xrange(len(self.issues)))

  @property
  def nb_drive_by(self):
    """Number of issues that got a drive by by this user, e.g. the user never
    got a formal issue review request.
    """
    return sum(r == self.DRIVE_BY for r in self.review_types)

  @property
  def nb_not_requested(self):
    """Number of issues where the reviewer sent his comments without the author
    even asking for a review. This can happen if the author asked for a review
    out of band, like by IM.
    """
    return sum(r == self.NOT_REQUESTED for r in self.review_types)

  @property
  def nb_outgoing(self):
    """Number of issues the user sent."""
    return sum(r == self.OUTGOING for r in self.review_types)

  @property
  def self_love(self):
    """How much the user likes to auto-congratulate himself on his own reviews.
    """
    # self.self_love + self.nb_lgtmed == sum(l > 0 for l in self.lgtms[i])
    return sum(
        self.review_types[i] == self.OUTGOING and self.lgtms[i] > 0
        for i in xrange(len(self.issues)))

  @property
  def latencies_sorted(self):
    return sorted(self.latencies)

  @property
  def median_latency(self):
    """Calculates the median latency to store in the datastore."""
    latencies = sorted(l for l in self.latencies if l >= 0)
    if not latencies:
      return None
    length = len(latencies)
    if (length & 1) == 0:
      return (latencies[length/2] + latencies[length/2-1]) / 2.
    else:
      return latencies[length/2]

  @property
  def average_latency(self):
    """The average review latency.

    The average is much less useful than the median, since the distribution is
    more Poisson-like than a bell curve.
    """
    latencies = [l for l in self.latencies if l >= 0]
    if not latencies:
      return None
    return sum(latencies) / float(len(latencies))

  @property
  def percent_reviewed(self):
    """Percentage of issues reviewed out of total incoming issues."""
    if not self.nb_issues:
      return 0
    return self.nb_reviewed * 100. / self.nb_issues

  @property
  def percent_lgtm(self):
    """Percentage of issues LGTMed out of total incoming issues."""
    if not self.nb_issues:
      return 0
    return self.nb_lgtmed * 100. / self.nb_issues

  @property
  def user(self):
    """Returns the corresponding Account key: the user's email address."""
    return self.key.parent().id()[1:-1]

  @property
  def user_short(self):
    """Strips the last part of domain off |.user| to save space."""
    return self.key.parent().id()[1:-1].rsplit('.', 1)[0]

  def _pre_put_hook(self):
    """Updates the score before saving."""
    # Save headaches and asserts internal consistency. This code can be
    # commented out once its is known to work.
    assert (
        len(self.issues) == len(self.lgtms) == len(self.latencies) ==
        len(self.review_types)), str(self)
    assert all(i >= 0 for i in self.lgtms), str(self)
    assert all(i >= -1 for i in self.latencies), str(self)
    assert all(self.NORMAL <= i <= self.OUTGOING for i in self.review_types), (
        str(self))
    for i in xrange(len(self.issues)):
      r = self.review_types[i]
      lg = self.lgtms[i]
      la = self.latencies[i]
      assert not (lg and r == self.IGNORED), str(self)
      if la >= 0:
        assert r in (self.NORMAL, self.DRIVE_BY, self.NOT_REQUESTED), str(self)
      else:
        assert r in (self.IGNORED, self.OUTGOING), str(self)

    # Always recalculate the score.
    self.score = compute_score(self)

  def to_dict(self):
    out = super(AccountStatsBase, self).to_dict()
    del out['modified']
    return out


class AccountStatsDay(AccountStatsBase):
  """Statistics for a single day.

  Using a separate entity type for summaries saves an index.
  """
  days = 1


class AccountStatsMulti(AccountStatsBase):
  # Cache the number of days covered by this entity.
  _days = None

  @property
  def days(self):
    """Number of days covered by this entity.

    Guaranteed to be >=1.
    """
    if not self._days:
      if self.name.isdigit():
        # It is a rolling summary.
        self._days = int(self.name)
      else:
        quarter = quarter_to_months(self.name)
        if not quarter:
          # It's a month.
          year, month = self.name.split('-', 1)
          self._days = calendar.monthrange(int(year), int(month))[1]
        else:
          self._days = sum(
              calendar.monthrange(map(int, i.split('-')))[1] for i in quarter)
    return self._days

  @property
  def per_day_reviews_received(self):
    """Average number of issues incoming per day."""
    return float(self.nb_issues) / self.days

  @property
  def per_day_reviews_done(self):
    """Average number of reviews done per day.

    Including drive bys, unrequested and self reviews.
    """
    return float(self.nb_reviewed) / self.days


def quarter_to_months(when):
  """Manually handles the form 'YYYY-QX'."""
  quarter = re.match(r'^(\d\d\d\d-)[qQ]([1-4])$', when)
  if not quarter:
    return None
  prefix = quarter.group(1)
  # Convert the quarter into 3 months group.
  base = (int(quarter.group(2)) - 1) * 4 + 1
  return ['%s%02d' % (prefix, i) for i in range(base, base+3)]


def verify_account_statistics_name(name):
  """Returns True if the key name is valid for an entity."""
  if name.isdigit():
    # Only allows 30 rolling days for now.
    return name == '30'

  if not re.match(r'^\d\d\d\d-\d\d(|-\d\d)$', name):
    return False
  # At that point, it's guaranteed to be somewhat date formed. Validate it's a
  # valid calendar day or month.
  parts = map(int, name.split('-'))
  # Accept only years [2008-current].
  if parts[0] > datetime.date.today().year or parts[0] < 2008:
    return False

  try:
    # Verify the calendar date.
    if len(parts) == 3:
      datetime.date(*parts)
    else:
      datetime.date(*parts, day=1)
    return True
  except ValueError:
    return False


def sum_account_statistics(out, items):
  """Updates |out| entity with the sum of all |items|.

  Returns True if the entity changed, False if the same values were calculated.
  In that case, it's not necessary to save the entity back in the datastore,
  it's unchanged.
  """
  prev_issues = out.issues
  prev_latencies = out.latencies
  prev_lgtms = out.lgtms
  prev_review_types = out.review_types

  out.issues = sum((i.issues for i in items), [])
  out.latencies = sum((i.latencies for i in items), [])
  out.lgtms = sum((i.lgtms for i in items), [])
  out.review_types = sum((i.review_types for i in items), [])
  out.score = compute_score(out)
  return (
      prev_issues != out.issues or
      prev_latencies != out.latencies or
      prev_lgtms != out.lgtms or
      prev_review_types != out.review_types)
