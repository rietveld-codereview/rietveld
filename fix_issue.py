import datetime
import logging
from mapreduce import operation as op
from codereview.models import Account


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
    canonical_date = datetime.datetime(2011, 05, 20)
    if account.modified >= canonical_date:
      logging.info('Account win! issue %d %s %s != %s' % (
          iid, email, i_uid, a_uid))
      issue.owner = account.user
      yield op.db.Put(issue)
