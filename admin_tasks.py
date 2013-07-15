"""Collection of mapreduce jobs."""

import logging
from mapreduce import operation as op
from codereview.models import Issue


def delete_unused_accounts(account):
  """Delete accounts for uses that don't participate in any reviews."""
  email = account.user.email()
  if Issue.all().filter('owner_email =', email).get():
    return
  if Issue.all().filter('cc =', email).get():
    return
  if Issue.all().filter('reviewers =', email).get():
    return
  logging.warn('Deleting %s' % email)
  yield op.db.Delete(account)
