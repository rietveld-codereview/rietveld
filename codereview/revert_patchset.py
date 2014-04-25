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

"""Contains the revert_patchset view."""

import hashlib
import re
import time

from codereview import decorators as deco
from codereview import exceptions
from codereview import invert_patches
from codereview import models
from codereview import views
from codereview.responses import HttpTextResponse

from google.appengine.ext import db
from google.appengine.runtime import DeadlineExceededError

from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect


# Constants for patch checks.
LARGE_PATCH_CHARS_THRESHOLD = 500000
MAX_LARGE_PATCHES_REVERSIBLE = 5

ERROR_MSG_POSTPEND = ' Please revert manually.\nSorry for the inconvenience.'

# We make it easier to revert recent CLs by adding a TBR= line.  We don't do
# that for older CLs because they are less likely to be urgent and more
# likely to require careful review of the revert itself.
# It would be great if we could know that the signed-in user was a sheriff.
MAX_TBR_AGE_SECS = 60 * 60 * 24 * 14


def _get_revert_description(request, revert_reason, reviewers, original_issue):
  """Creates and returns a description for the revert CL."""
  revert_description = []
  # Contain link to original CL.
  original_issue_link = request.build_absolute_uri(
      reverse('codereview.views.show', args=[original_issue.key().id()]))
  revert_description.append('Revert of %s (%s)' % (original_issue.subject,
                                                   original_issue_link))
  # Display the reason for reverting.
  revert_description.append('')  # Extra new line to separate sections.
  revert_description.append('Reason for revert:')
  revert_description.append('%s' % revert_reason)

  # Add the original issue's decription.
  revert_description.append('')  # Extra new line to separate sections.
  revert_description.append('Original issue\'s description:')
  for line in original_issue.description.split('\n'):
    revert_description.append('> %s' % line)

  age = int(time.time()) - time.mktime(original_issue.created.timetuple())
  if age < MAX_TBR_AGE_SECS:
    # TBR original author + reviewers.
    revert_description.append('')  # Extra new line to separate sections.
    revert_description.append('TBR=%s' % ','.join(
        [str(reviewer) for reviewer in reviewers]))
    # Skip tree status checks.
    revert_description.append('NOTREECHECKS=true')
    # Do not run trybots on the revert CL.
    revert_description.append('NOTRY=true')
    # Check to see if the original description contains "BUG=" if it does then
    # use it in the revert description.
    match_bugline = re.search(
      r'^\s*(BUG=.*)$', original_issue.description or '', re.M | re.I)
    if match_bugline:
      revert_description.append('%s' % match_bugline.groups(0))

  return '\n'.join(revert_description)


def _get_revert_subject(original_subject):
  """Creates and returns a subject for the revert CL."""
  return 'Revert of %s' % original_subject


def check_patches_reversable(patches):
  """Check to see if the specified patches are reversible.

    Returns True if it is else throws an Error with why it is not reversible.
  """
  large_patches = 0
  for patch in patches:

    # If the patch status is 'None' it could be due to an incompletely uploaded
    # original patch.
    if not patch.status:
      raise exceptions.RevertError('Found a None patch status. The original '
          'patchset may have been incompletely uploaded.')

    # Collect the number of large patches.
    if len(patch.text) > LARGE_PATCH_CHARS_THRESHOLD:
      large_patches += 1

    # Only git patches are supported.
    diff_header = invert_patches.split_header(patch.text)[0]
    if not invert_patches.is_git_diff_header(diff_header):
      raise exceptions.RevertError('Can only invert Git patches.')

    if re.search(r"(?m)^similarity index 100%", diff_header):
      # We cannot invert A+ patches with 100% similarity index because they do
      # not contain the git SHA-1 indexes. Rietveld currently stores only MD5
      # checksums of data in Content, it would require a significant change to
      # support this.
      raise exceptions.RevertError(
          'Unable to inverse \'A +\' patches with 100% similarity indexes.')

  if large_patches > MAX_LARGE_PATCHES_REVERSIBLE:
    raise exceptions.RevertError('The Patchset is too large to invert.')
  return True


@deco.xsrf_required
@deco.patchset_editor_required
def revert_patchset(request):
  """/api/<issue>/<patchset>/revert_patchset - Create an inverted changeset."""

  if request.method != 'POST':
    return HttpTextResponse(
        '/revert_issue only supports POST.', status=403)

  # Find the patches of the issue we want to revert.
  original_issue = request.issue
  original_patchset = request.patchset
  original_patches = original_patchset.patches

  # Make sure the original issue is closed.
  assert original_issue.closed, 'The original issue must be closed.'
  # Make sure the requesting user has access to view the original issue.
  assert original_issue.user_can_view(request.user), (
      'You do not have permission to view or revert this issue.')

  # Validate that all original patches are supported by /revert_patchset.
  try:
    check_patches_reversable(original_patches)
  except exceptions.RevertError, e:
    return HttpTextResponse(e.message + ERROR_MSG_POSTPEND, status=404)

  # Create the new revert issue to use as the key in the new patchset.
  issue_key = db.Key.from_path(
      models.Issue.kind(),
      db.allocate_ids(db.Key.from_path(models.Issue.kind(), 1), 1)[0])

  reviewers = original_issue.reviewers
  original_owner = original_issue.owner
  # Add the original_owner to the list of reviewers if different from the
  # current user.
  if original_owner.email() != request.user.email():
    reviewers.append(db.Email(original_owner.email()))
  # Remove current user from the reviewers.
  if request.user.email() in reviewers:
    reviewers.remove(db.Email(request.user.email()))

  # Datastructure that will hold all pending Issue, PatchSet, Patches and
  # Contents of the revert Issue.
  pending_commits = []

  subject = _get_revert_subject(original_issue.subject)
  revert_reason = request.POST['revert_reason']
  revert_cq = request.POST['revert_cq'] == '1'
  description = _get_revert_description(
      request, revert_reason, reviewers, original_issue)
  issue = models.Issue(subject=subject,
                       description=description,
                       base=original_issue.base,
                       repo_guid=original_issue.repo_guid,
                       reviewers=reviewers,
                       cc=original_issue.cc,
                       private=original_issue.private,
                       n_comments=0,
                       commit=False,  # Do not check the commit box yet.
                       key=issue_key)
  pending_commits.append(issue);

  # Create the new revert patchset to use as the key in the new patches.
  ps_key = db.Key.from_path(
      models.PatchSet.kind(),
      db.allocate_ids(db.Key.from_path(models.PatchSet.kind(), 1,
                                       parent=issue.key()), 1)[0],
      parent=issue.key())
  patchset = models.PatchSet(
      issue=issue,
      url=None,
      key=ps_key)
  pending_commits.append(patchset)

  # Loop through all the original patches and create inversions.
  for original_patch in original_patches:

    try:
      patch = original_patch.make_inverted(patchset)
    except DeadlineExceededError:
      return HttpTextResponse(
          'The patchset is too large to invert. Please revert manually.\n'
          'Sorry for the inconvenience.', status=500)
    except exceptions.RevertError, e:
      return HttpTextResponse(e.message + ERROR_MSG_POSTPEND, status=404)

    # Find the original content and patched content.
    if original_patch.is_binary:
      original_content = original_patch.content
      original_patched_content = original_patch.patched_content
    else:
      original_content = original_patch.get_content()
      original_patched_content = original_patch.get_patched_content()

    # Allocate keys for content and patched_content.
    content_key = db.Key.from_path(
        models.Content.kind(),
        db.allocate_ids(db.Key.from_path(models.Content.kind(), 1,
                                         parent=patch.key()), 1)[0],
        parent=patch.key())
    patched_content_key = db.Key.from_path(
        models.Content.kind(),
        db.allocate_ids(db.Key.from_path(models.Content.kind(), 1,
                                         parent=patch.key()), 1)[0],
        parent=patch.key())

    if original_patch.patched_content:
      content = models.Content(
        key=content_key,
        text=original_patched_content.text,
        data=original_patched_content.data,
        checksum=original_patched_content.checksum,
        is_uploaded=original_patched_content.is_uploaded,
        is_bad=original_patched_content.is_bad,
        file_too_large=original_patched_content.file_too_large)
    else:
      # Create an empty content if there is no patched_content.
      empty_data = db.Blob()
      content = models.Content(
        key=content_key,
        text='',
        data=empty_data,
        checksum=hashlib.md5(empty_data).hexdigest(),
        is_uploaded=True,
        is_bad=False,
        file_too_large=False)

    if original_patch.status != invert_patches.COPIED_AND_MODIFIED_STATUS:
      patched_content = models.Content(
          key=patched_content_key,
          text=original_content.text,
          data=original_content.data,
          checksum=original_content.checksum,
          is_uploaded=original_content.is_uploaded,
          is_bad=original_content.is_bad,
          file_too_large=original_content.file_too_large)
    else:
      # Create an empty patched content if it is an 'A +' status. This is
      # because the inverted status becomes a 'D' request.
      empty_data = db.Blob()
      patched_content = models.Content(
        key=patched_content_key,
        text='',
        data=empty_data,
        checksum=hashlib.md5(empty_data).hexdigest(),
        is_uploaded=True,
        is_bad=False,
        file_too_large=False)

    pending_commits.append(content)
    pending_commits.append(patched_content)

    patch.content = content
    patch.patched_content = patched_content
    pending_commits.append(patch)

  # Commit the gathered revert Issue, PatchSet, Patches and Contents.
  _db_commit_all_pending_commits(pending_commits)

  # Notify the original issue that a revert issue has been created.
  revert_issue_link = request.build_absolute_uri(
      reverse('codereview.views.show', args=[issue.key().id()]))
  revert_message = (
      'A revert of this CL has been created in %s by %s.\n\nThe reason for '
      'reverting is: %s.' % (revert_issue_link, request.user.email(),
                             revert_reason))
  views.make_message(request, original_issue, revert_message,
                     send_mail=True).put()
  # Notify the revert issue recipients.
  views.make_message(request, issue, 'Created %s' % subject,
                     send_mail=True).put()

  # Now that all patchsets and patches have been committed check the commit box
  # if the revert_cq checkbox was checked.
  if revert_cq:
    issue.commit = True
  issue.put()

  return HttpResponseRedirect(reverse('codereview.views.show',
                                      args=[issue.key().id()]))


def _db_commit_all_pending_commits(pending_commits):
  """Puts all pending commits into the DB."""
  for pending_commit in pending_commits:
    pending_commit.put()
