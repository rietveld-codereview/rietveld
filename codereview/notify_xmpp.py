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

import logging

from google.appengine.api import xmpp

from django.core.urlresolvers import reverse

from . import models
from . import decorators as deco
from .responses import HttpTextResponse


def get_chat_status(account):
  try:
    presence = xmpp.get_presence(account.email)
    return 'online' if presence else 'offline'
  except Exception as err:
    logging.error('Exception getting XMPP presence: %s', err)
    return 'Error (%s)' % err


@deco.require_methods('POST')
def incoming_chat(request):
  """/_ah/xmpp/message/chat/

  This handles incoming XMPP (chat) messages.

  Just reply saying we ignored the chat.
  """
  try:
    msg = xmpp.Message(request.POST)
  except xmpp.InvalidMessageError, err:
    logging.warn('Incoming invalid chat message: %s' % err)
    return HttpTextResponse('')
  sts = msg.reply('Sorry, Rietveld does not support chat input')
  logging.debug('XMPP status %r', sts)
  return HttpTextResponse('')


def must_invite(account):
  logging.info('Sending XMPP invite to %s', account.email)
  try:
    xmpp.send_invite(account.email)
  except Exception:
    # XXX How to tell user it failed?
    logging.error('XMPP invite to %s failed', account.email)


def notify_issue(request, issue, message):
  """Try sending an XMPP (chat) message.

  Args:
    request: The request object.
    issue: Issue whose owner and reviewers are to be notified.
    message: Text of message to send, e.g. 'Created'.

  The current user and the issue's subject and URL are appended to the message.

  Returns:
    True if the message was (apparently) delivered, False if not.
  """
  iid = issue.key().id()
  emails = set()
  emails.add(issue.owner.email())
  if issue.reviewers:
    emails.update(issue.reviewers)
  if request.user:
    # Do not XMPP the person who made the rietveld modifications.
    # See https://code.google.com/p/rietveld/issues/detail?id=401.
    emails.discard(request.user.email())
  accounts = models.Account.get_multiple_accounts_by_email(emails)
  jids = []
  for account in accounts.itervalues():
    logging.debug('email=%r,chat=%r', account.email, account.notify_by_chat)
    if account.notify_by_chat:
      jids.append(account.email)
  if not jids:
    logging.debug('No XMPP jids to send to for issue %d', iid)
    return True  # Nothing to do.
  jids_str = ', '.join(jids)
  logging.debug('Sending XMPP for issue %d to %s', iid, jids_str)
  sender = '?'
  if models.Account.current_user_account:
    sender = models.Account.current_user_account.nickname
  elif request.user:
    sender = request.user.email()
  message = '%s by %s: %s\n%s' % (message,
                                  sender,
                                  issue.subject,
                                  request.build_absolute_uri(
                                    reverse('codereview.views.show',
                                            args=[iid])))
  try:
    sts = xmpp.send_message(jids, message)
  except Exception, err:
    logging.exception('XMPP exception %s sending for issue %d to %s',
                      err, iid, jids_str)
    return False
  else:
    if sts == [xmpp.NO_ERROR] * len(jids):
      logging.info('XMPP message sent for issue %d to %s', iid, jids_str)
      return True
    else:
      logging.error('XMPP error %r sending for issue %d to %s',
                    sts, iid, jids_str)
      return False
