import datetime
import logging
from mapreduce import operation as op
from codereview.models import Account, Issue, TryJobResult


def FixIssue(issue):
  email = issue.owner.email()
  account = Account.get_by_key_name('<%s>' % email)
  iid = issue.key().id()
  if not account:
    logging.error('Issue %d has owner %s which doesn\'t exist' % (iid, email))
    return

  i_uid = issue.owner.user_id()
  a_uid = account.user.user_id()
  if i_uid != a_uid:
    canonical_date = datetime.datetime(2011, 07, 01)
    if account.modified >= canonical_date:
      logging.info('Account win! issue %d %s %s != %s' % (
          iid, email, i_uid, a_uid))
      issue.owner = account.user
      yield op.db.Put(issue)


def DeleteUnusedAccounts(account):
  email = account.user.email()
  if Issue.query(Issue.owner_email == email).get():
    return
  if Issue.query(Issue.cc == email).get():
    return
  if Issue.query(Issue.reviewers == email).get():
    return
  logging.warn('Deleting %s' % email)
  yield op.db.Delete(account)


def UpgradeBuildResults(patchset):
  """Convert the old build_results member of PatchSet to TryJobResults.

  For each entry in the build_results field in patchset, create an instance
  of TryJobResult with the corresponding information.  The build_results field
  is then removed from the patchset.

  Args:
    patchset: An entity of the model PatchSet.
  """
  SEPARATOR = '|'
  objects_to_save = []

  if patchset.build_results:
    for build_result in patchset.build_results:
      try:
        (platform_id, status, details_url) = build_result.split(SEPARATOR, 2)
        if status == 'success':
          result = TryJobResult.SUCCESS
        elif status == 'failure':
          result = TryJobResult.FAILURE
        else:
          result = -1
        job = TryJobResult(parent=patchset,
                           url=details_url,
                           result=result,
                           builder=platform_id,
                           timestamp=patchset.modified)
        objects_to_save.append(job)
      except ValueError:
        logging.warn('Invalid build_result %s for patchset %d/%d',
                     build_result,
                     patchset.issue.key().id(),
                     patchset.key().id())

    patchset.build_results = []
    objects_to_save.append(patchset)

  class Put(op.base.Operation):
    def __call__(self, context):
      for obj in objects_to_save:
        context.mutation_pool.put(obj)

  yield Put()

def RemoveNMessagesSentFromIssues(issue):
  """Causes Issues to re-cache their message_set-based data."""
  if issue.n_messages_sent is not None:
    issue.n_messages_sent = None
    yield op.db.Put(issue)
