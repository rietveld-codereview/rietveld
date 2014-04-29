"""Collection of mapreduce jobs."""

import logging
from mapreduce import operation as op
from codereview.models import Account, Issue


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


def update_account_schema(account):
  """Update schema for all Accounts by saving them back to the datastore."""

  # Make sure we don't alter the modified time of any accounts. Because of how
  # mapreduce is designed, we just set this to False on every function
  # invocation (since there's no convenient once-per-instance place to do it).
  Account.modified.auto_now = False

  yield op.db.Put(account)
