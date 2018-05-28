#!/usr/bin/env python
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

"""Tests for views.py stats functions and helpers."""

# TODO: fix these tests and rename them back to test_views_stats.py.
# The stats feature is complex and broken right now and it should
# not make other development harder.


import datetime
import json
import re
import sys
import unittest

import setup
setup.process_args()


from django.http import HttpRequest

from google.appengine.api.users import User
from google.appengine.ext import db
from google.appengine.ext import ndb

import utils

from codereview import models
from codereview import views
from codereview import engine  # engine must be imported after models :(

# Shortcuts
NORMAL = models.AccountStatsBase.NORMAL
IGNORED = models.AccountStatsBase.IGNORED
DRIVE_BY = models.AccountStatsBase.DRIVE_BY
NOT_REQUESTED = models.AccountStatsBase.NOT_REQUESTED
OUTGOING = models.AccountStatsBase.OUTGOING


def format_header(head):
  return ('http_' + head).replace('-', '_').upper()


class MockRequestTask(HttpRequest):
  """Mock request class for testing."""
  def __init__(self, queue, tasks, date):
    super(MockRequestTask, self).__init__()
    self.method = 'POST'
    self.META['HTTP_HOST'] = 'testserver'
    key = format_header('X-AppEngine-QueueName')
    self.META[key] = queue
    self.POST['tasks'] = json.dumps(tasks)
    self.POST['date'] = date


class MockRequestGet(HttpRequest):
  """Mock request class for testing."""
  def __init__(self):
    super(MockRequestGet, self).__init__()
    self.META['HTTP_HOST'] = 'testserver'
    self.REQUEST = {}
    self.user = None
    self.user_is_admin = False


class TestCase(utils.TestCase):
  def setUp(self):
    super(TestCase, self).setUp()
    # Kill auto_now and auto_now_add support.
    models.Issue.created._auto_now_add = False
    models.Issue.modified._auto_now = False
    
  def tearDown(self):
    # Restore auto_now and auto_now_add support.
    models.Issue.created._auto_now_add = True
    models.Issue.modified._auto_now = True
    super(TestCase, self).setUp()

class TestDailyStats(TestCase):
  def setUp(self):
    super(TestDailyStats, self).setUp()
    self.author = models.Account.get_account_for_user(
        User('author@example.com'))
    self.reviewer1 = models.Account.get_account_for_user(
        User('reviewer1@example.com'))
    self.reviewer2 = models.Account.get_account_for_user(
        User('reviewer2@example.com'))
    # Real users have created at least one issue.
    models.Issue(owner=self.author.user, subject='Damned').put()
    models.Issue(owner=self.reviewer1.user, subject='Damned').put()
    models.Issue(owner=self.reviewer2.user, subject='Damned').put()

  def create_issue(self, date, reviewers=None, cc=None):
    """Creates an issue by self.author with self.reviewer1 as a reviewer."""
    date = datetime.datetime.strptime('2011-03-' + date, '%Y-%m-%d %H:%M')
    issue = models.Issue(
        subject='test',
        owner=self.author.user,
        reviewers=[r.email for r in reviewers or [self.reviewer1]],
        cc=[db.Email('mailinglist@example.com')] + [c.email for c in cc or []],
        created=date,
        modified=date)
    issue.put()
    # Verify that our auto_now hack works.
    self.assertEqual(issue.key.get().created, date)
    self.assertEqual(issue.key.get().modified, date)
    ps = models.PatchSet(
      parent=issue.key, issue_key=issue.key, created=date, modified=date)
    ps.data = utils.load_file('ps1.diff')
    ps.put()
    patches = engine.ParsePatchSet(ps)
    ndb.put_multi(patches)
    return issue

  def add_message(self, issue, sender, recipients, date, text):
    """Adds a Message."""
    date = datetime.datetime.strptime('2011-03-' + date, '%Y-%m-%d %H:%M')
    models.Message(
        parent=issue.key,
        issue_key=issue.key,
        subject='Your code is great',
        sender=sender.email,
        recipients=[r.email for r in recipients],
        date=date,
        text=text).put()

  def trigger_request(self, date, text, expected):
    """Triggers a fake HTTP request and verifies the AccountStatsDay instances.
    """
    request = MockRequestTask('update-stats', [date], date)
    out = views.task_update_stats(request)
    self.assertEqual(200, out.status_code)
    actual = list(out)
    self.assertEqual(1, len(actual))

    stats = models.AccountStatsDay.query().fetch()
    self.assertTrue(isinstance(expected, list))
    # Make a copy so |expected| is not modified.
    expected = [i.copy() for i in expected]
    for i in expected:
      i['user'] = str(i['user'].email)
      i.setdefault('issues', [4])
      i.setdefault('latencies', [-1])
      i.setdefault('lgtms', [0])
      i.setdefault('name', date)
      i.setdefault('score', models.AccountStatsBase.NULL_SCORE)
    self.assertEqual(expected, [views.stats_to_dict(s) for s in stats])
    # Check the HTTP request reply at the end, because it's more cosmetic than
    # the actual entities.
    self.assertTrue(
        re.match('^' + re.escape(date + '\n' + text) + 'In \\d+\\.\\ds\n$', actual[0]),
        actual[0])

  def test_normal_lgtm(self):
    # Normal reviewer with lgtm.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    self.add_message(issue, self.reviewer1, [self.author], '01 01:03', 'lgtm')
    text = '2 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'latencies': [-1],
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [120],
        'lgtms': [1],
        'review_types': [NORMAL],
        'score': 1.2,
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_normal(self):
    # Normal review without lgtm.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    self.add_message(
        issue, self.reviewer1, [self.author], '01 01:03', 'no lgtm')
    text = '2 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'latencies': [-1],
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [120],
        'review_types': [NORMAL],
        'score': 1.2,
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_unreviewed(self):
    # The reviewer is MIA.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_not_requested(self):
    # An issue was uploaded and someone else reviewed the issue, without the
    # author ever sending a request for review.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.reviewer1, [self.author], '01 02:00', 'lgtm')
    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [3600],
        'lgtms': [1],
        'review_types': [NOT_REQUESTED],
        'score': 36.0,
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_drive_by(self):
    # Another reviewer drives-by.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    self.add_message(issue, self.reviewer2, [self.author], '01 01:03', 'lgtm')
    text = '2 messages\n1 issues\nUpdated 3 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
      {
        'latencies': [120],
        'lgtms': [1],
        'review_types': [DRIVE_BY],
        'score': 1.2,
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_selfreview(self):
    # Someone lgtm himself.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    self.add_message(issue, self.author, [self.author], '01 01:03', 'lgtm')
    text = '2 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'lgtms': [1],
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def setup_selfreview_multiday(self):
    # Someone lgtm himself after waiting one day.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    self.add_message(issue, self.author, [self.author], '02 01:03', 'lgtm')

  def test_selfreview_multiday_1(self):
    self.setup_selfreview_multiday()
    text = '2 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_selfreview_multiday_2(self):
    self.setup_selfreview_multiday()
    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'lgtms': [1],
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'name': '2011-03-01',
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-02', text, expected)

  def test_reviewer_added_on_followup(self):
    # An issue is published for review. Later the author add another reviewer
    # and the reviewer replies. The latency must be calculated on the moment the
    # reviewer was on the recipients list.
    issue = self.create_issue('01 01:00', [self.reviewer1, self.reviewer2])
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    # Base timestamp for reviewer2 latency.
    self.add_message(
        issue, self.author, [self.reviewer1, self.reviewer2], '01 01:10',
        'reviewer1 is slacking, reviewer2 ptal.')
    self.add_message(
        issue, self.reviewer2, [self.reviewer1, self.reviewer2], '01 01:12',
        'lgtm')
    text = '3 messages\n1 issues\nUpdated 3 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
      {
        'latencies': [120],
        'lgtms': [1],
        'review_types': [NORMAL],
        'score': 1.2,
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def setup_multiday(self):
    # Normal reviewer with lgtm. Make sure updating is done on the right day.
    issue = self.create_issue('01 01:00', [self.reviewer1, self.reviewer2])
    self.add_message(issue, self.author, [self.reviewer1], '02 01:01', '')
    self.add_message(
        issue, self.reviewer1, [self.author], '03 00:01',
        'I don\'t have time, find someone else')
    self.add_message(
        issue, self.author, [self.reviewer1, self.reviewer2], '04 10:01',
        'reviewer1 is slacking, reviewer2 ptal.')
    self.add_message(
        issue, self.reviewer2, [self.reviewer1, self.reviewer2], '05 03:01',
        'lgtm')

  def test_multidays_1(self):
    self.setup_multiday()
    text = '0 messages\n0 issues\nUpdated 0 items\n'
    expected = []
    self.trigger_request('2011-03-01', text, expected)

  def test_multidays_2(self):
    self.setup_multiday()
    # It's normal that messages is overcounted.
    text = '4 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'name': '2011-03-02',
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-02', text, expected)

  def test_multidays_3(self):
    self.setup_multiday()
    # It's normal that messages is overcounted.
    text = '3 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [82800],
        'name': '2011-03-02',
        'review_types': [NORMAL],
        'score': 828.0,
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-03', text, expected)

  def test_multidays_4(self):
    self.setup_multiday()
    # It's normal that messages is overcounted.
    text = '2 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'name': '2011-03-04',
        'review_types': [IGNORED],
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-04', text, expected)

  def test_multidays_5(self):
    self.setup_multiday()
    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [61200],
        'lgtms': [1],
        'name': '2011-03-04',
        'review_types': [NORMAL],
        'score': 612.0,
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-05', text, expected)

  def test_multidays_6(self):
    self.setup_multiday()
    text = '0 messages\n0 issues\nUpdated 0 items\n'
    expected = []
    self.trigger_request('2011-03-06', text, expected)

  def test_multidays_all(self):
    # Ensures that running all the tasks one after the other results in proper
    # values.
    self.setup_multiday()

    # test_multidays_1
    text = '0 messages\n0 issues\nUpdated 0 items\n'
    expected = []
    self.trigger_request('2011-03-01', text, expected)

    # test_multidays_2
    text = '4 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'name': '2011-03-02',
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-02', text, expected)

    # test_multidays_3
    text = '3 messages\n1 issues\nUpdated 1 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [82800],
        'name': '2011-03-02',
        'review_types': [NORMAL],
        'score': 828.0,
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-03', text, expected)

    # test_multidays_4; expected is different than the stand alone test case
    # because accumulates from previous tasks.
    text = '2 messages\n1 issues\nUpdated 1 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [82800],
        'name': '2011-03-02',
        'review_types': [NORMAL],
        'score': 828.0,
        'user': self.reviewer1,
      },
      {
        'name': '2011-03-04',
        'review_types': [IGNORED],
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-04', text, expected)

    # test_multidays_5; expected is different than the stand alone test case
    # because accumulates from previous tasks.
    text = '1 messages\n1 issues\nUpdated 1 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [82800],
        'name': '2011-03-02',
        'review_types': [NORMAL],
        'score': 828.0,
        'user': self.reviewer1,
      },
      {
        'latencies': [61200],
        'lgtms': [1],
        'name': '2011-03-04',
        'review_types': [NORMAL],
        'score': 612.0,
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-05', text, expected)

    # test_multidays_6; no change from test_multidays_5.
    text = '0 messages\n0 issues\nUpdated 0 items\n'
    self.trigger_request('2011-03-06', text, expected)

  def test_multidays_all_reversed(self):
    # Ensures that running the tasks in reverse order is idempotent. The end
    # result must be the same as test_multidays_all().
    self.setup_multiday()

    text = '0 messages\n0 issues\nUpdated 0 items\n'
    expected = []
    self.trigger_request('2011-03-06', text, expected)

    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [61200],
        'lgtms': [1],
        'name': '2011-03-04',
        'review_types': [NORMAL],
        'score': 612.0,
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-05', text, expected)

    text = '2 messages\n1 issues\nUpdated 0 items\n'
    self.trigger_request('2011-03-04', text, expected)

    text = '3 messages\n1 issues\nUpdated 1 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [82800],
        'name': '2011-03-02',
        'review_types': [NORMAL],
        'score': 828.0,
        'user': self.reviewer1,
      },
      {
        'latencies': [61200],
        'lgtms': [1],
        'name': '2011-03-04',
        'review_types': [NORMAL],
        'score': 612.0,
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-03', text, expected)

    text = '4 messages\n1 issues\nUpdated 0 items\n'
    self.trigger_request('2011-03-02', text, expected)

    text = '0 messages\n0 issues\nUpdated 0 items\n'
    self.trigger_request('2011-03-01', text, expected)

  def test_multidays_no_lgtm_reversed(self):
    # Special case with no lgtm, reducing the potential optimisations. Make sure
    # reversed processing is still idempotent.
    issue = self.create_issue('01 01:00', [self.reviewer1, self.reviewer2])
    # Note that reviewer2 is not emailed.
    self.add_message(issue, self.author, [self.reviewer1], '01 01:01', '')
    self.add_message(
        issue, self.reviewer1, [self.author], '02 01:01', 'blah')
    # reviewer1 added reviewer2. That's when his latency will start. Note that
    # it is a third party that added him!
    self.add_message(
        issue, self.reviewer1, [self.author, self.reviewer2], '03 01:01',
        'I don\'t care.')

    text = '0 messages\n0 issues\nUpdated 0 items\n'
    expected = []
    self.trigger_request('2011-03-04', text, expected)

    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'name': '2011-03-03',
        'review_types': [IGNORED],
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-03', text, expected)

    text = '2 messages\n1 issues\nUpdated 1 items\n'
    expected = [
      {
        'name': '2011-03-01',
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [86400],
        'name': '2011-03-01',
        'review_types': [NORMAL],
        'score': 864.0,
        'user': self.reviewer1,
      },
      {
        'name': '2011-03-03',
        'review_types': [IGNORED],
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-02', text, expected)

    text = '3 messages\n1 issues\nUpdated 0 items\n'
    self.trigger_request('2011-03-01', text, expected)

  def disabled_test_1010_messages(self):
    # NOTE: It is disabled by default because it is extremely slow. It was
    # simply coded once to make sure the code was working with >1000 entities.
    #
    # Makes sure it works even if the number of Issue-Message is over 1000 in a
    # single day.
    count = 1010
    issues = [self.create_issue('01 01:00') for _ in xrange(count)]
    for i in xrange(count):
      self.add_message(
          issues[i], self.author, [self.reviewer1], '01 01:02', '.')
    expected = [
      {
        'issues': [i.key.id() for i in issues],
        'latencies': [-1] * count,
        'lgtms': [0] * count,
        'name': '2011-03-01',
        'review_types': [IGNORED] * count,
        'user': self.reviewer1,
      },
    ]
    text = '1010 messages\n1010 issues\nUpdated 1 items\n'
    self.trigger_request('2011-03-01', text, expected)

  def test_cc(self):
    # A user that is on the CC list, thus always in Message.recipients, but
    # never replied and not in Message.reviewers, should not be marked as
    # IGNORED but should be ignored instead.
    # This happens often in Chromium land with WATCHLISTS.
    issue = self.create_issue('01 01:00', [self.reviewer1], [self.reviewer2])
    self.add_message(
        issue, self.author, [self.reviewer1, self.reviewer2], '01 01:01', '')
    text = '1 messages\n1 issues\nUpdated 2 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_cc_and_reviewer(self):
    # A user that is on the CC list AND reviewers
    issue = self.create_issue(
        '01 01:00', [self.reviewer1, self.reviewer2], [self.reviewer2])
    self.add_message(
        issue, self.author, [self.reviewer1, self.reviewer2], '01 01:01', '')
    text = '1 messages\n1 issues\nUpdated 3 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer1,
      },
      {
        'review_types': [IGNORED],
        'user': self.reviewer2,
      },
    ]
    self.trigger_request('2011-03-01', text, expected)

  def test_not_requested_twice(self):
    # An issue was uploaded and someone else reviewed the issue, without the
    # author ever sending a request for review. Then a third person piled on.
    issue = self.create_issue('01 01:00')
    self.add_message(issue, self.reviewer1, [self.author], '01 02:00', 'lgtm')
    self.add_message(
        issue, self.reviewer2, [self.author, self.reviewer1], '01 03:10',
        'lovely, lgtm')
    text = '2 messages\n1 issues\nUpdated 3 items\n'
    expected = [
      {
        'review_types': [OUTGOING],
        'user': self.author,
      },
      {
        'latencies': [3600],
        'lgtms': [1],
        'review_types': [NOT_REQUESTED],
        'score': 36.0,
        'user': self.reviewer1,
      },
      {
        'latencies': [7800],
        'lgtms': [1],
        'review_types': [NOT_REQUESTED],
        'score': 78.0,
        'user': self.reviewer2,
        },
    ]
    self.trigger_request('2011-03-01', text, expected)


class TestMultiStats(TestCase):
  def setUp(self):
    super(TestMultiStats, self).setUp()
    self.assertEqual([], models.AccountStatsDay.query().fetch())
    self.assertEqual([], models.AccountStatsMulti.query().fetch())
    self.assertEqual(None, models.Issue.query().get())
    self.userA = models.Account.get_account_for_user(
        User('user_a@example.com'))
    self.userA_key = self.userA.key
    self.userB = models.Account.get_account_for_user(
        User('user_b@example.com'))
    self.userB_key = self.userB.key
    # Real users have created at least one issue.
    models.Issue(owner=self.userA.user, subject='Damned').put()
    models.Issue(owner=self.userB.user, subject='Damned').put()
    self.today = datetime.datetime(2012, 04, 30, 1, 0)
    self.yesterday = self.today - datetime.timedelta(days=1)

  def trigger_request(self, date, item, text, expected):
    """Triggers a fake HTTP request and verifies the AccountStatsMulti
    instances.
    """
    request = MockRequestTask('update-stats', [item], str(self.today.date()))
    out = views.task_update_stats(request)
    actual = list(out)
    self.assertEqual(1, len(actual))
    self.assertEqual(200, out.status_code, actual[0])

    stats = models.AccountStatsMulti.query().fetch()
    self.assertTrue(isinstance(expected, list))
    # Make a copy so |expected| is not modified.
    expected = [i.copy() for i in expected]
    for i in expected:
      i['user'] = str(i['user'].email)
    self.assertEqual(expected, [views.stats_to_dict(s) for s in stats])
    # Check the HTTP request reply at the end, because it's more cosmetic than
    # the actual entities.
    text = str(date.date()) + '\n' + text
    regexp = '^' + re.escape(text) + 'In \\d+\\.\\ds\n$'
    self.assertTrue(re.match(regexp, actual[0]), (text, actual[0]))

  def test_rolling(self):
    self.assertEqual([], models.AccountStatsDay.query().fetch())
    self.assertEqual([], models.AccountStatsMulti.query().fetch())
    # UserA
    models.AccountStatsDay(
        id='2012-04-20',
        parent=self.userA_key,
        issues=[1],
        latencies=[1],
        lgtms=[10],
        review_types=[NORMAL],
        modified=self.yesterday).put()
    models.AccountStatsDay(
        id='2012-04-10',
        parent=self.userA_key,
        issues=[13],
        latencies=[3],
        lgtms=[0],
        review_types=[NORMAL],
        modified=self.yesterday).put()
    # UserB
    models.AccountStatsDay(
        id='2012-04-28',
        parent=self.userB_key,
        issues=[3],
        latencies=[20],
        lgtms=[1],
        review_types=[DRIVE_BY],
        modified=self.yesterday).put()
    # Old instance.
    models.AccountStatsDay(
        id='2012-02-01',
        parent=self.userB_key,
        issues=[30, 13],
        latencies=[-1, 100],
        lgtms=[0, 1],
        review_types=[IGNORED, NORMAL],
        modified=self.yesterday).put()
    self.assertEqual(4, len(list(models.AccountStatsDay.query())))
    # Put a garbagge instance that will be overriden.
    models.AccountStatsMulti(
        id='30',
        parent=self.userB_key,
        issues=[1, 2, 3],
        latencies=[1, 2, 3],
        lgtms=[1, 2, 3],
        review_types=[NORMAL, NORMAL, NORMAL],
        modified=self.yesterday).put()

    expected = [
      {
        'issues': [1, 13],
        'latencies': [1, 3],
        'lgtms': [10, 0],
        'name': '30',
        'review_types': [NORMAL, NORMAL],
        'score': 0.01,
        'user': self.userA,
      },
      {
        'issues': [3],
        'latencies': [20],
        'lgtms': [1],
        'name': '30',
        'review_types': [DRIVE_BY],
        'score': 0.2,
        'user': self.userB,
      },
    ]
    text = 'Looked up 2 accounts\nStored 2 items\nDeleted 0\n'
    self.trigger_request(self.yesterday, '30', text, expected)

  def test_month(self):
    models.AccountStatsDay(
        id='2012-04-08',
        parent=self.userA_key,
        issues=[1],
        latencies=[1],
        lgtms=[10],
        review_types=[NORMAL],
        modified=self.yesterday).put()
    models.AccountStatsDay(
        id='2012-04-18',
        parent=self.userA_key,
        issues=[13],
        latencies=[3],
        lgtms=[0],
        review_types=[NORMAL],
        modified=self.yesterday).put()

    models.AccountStatsDay(
        id='2012-04-03',
        parent=self.userB_key,
        issues=[3],
        latencies=[30],
        lgtms=[1],
        review_types=[DRIVE_BY],
        modified=self.yesterday).put()
    models.AccountStatsDay(
        id='2012-05-02',
        parent=self.userB_key,
        issues=[30, 13],
        latencies=[-1, 1],
        lgtms=[0, 1],
        review_types=[IGNORED, NORMAL],
        modified=self.yesterday).put()
    self.assertEqual(4, len(list(models.AccountStatsDay.query())))

    # Put a garbagge instance.
    models.AccountStatsMulti(
        id='2011-03',
        parent=self.userB_key,
        issues=[1, 2, 3],
        latencies=[1, 2, 3],
        lgtms=[1, 2, 3],
        review_types=[NORMAL, NORMAL, NORMAL],
        modified=self.yesterday).put()

    expected = [
      {
        'issues': [1, 13],
        'latencies': [1, 3],
        'lgtms': [10, 0],
        'name': '2012-04',
        'score': 0.01,
        'review_types': [NORMAL, NORMAL],
        'user': self.userA,
      },
      {
        # Old instance.
        'issues': [1, 2, 3],
        'latencies': [1, 2, 3],
        'lgtms': [1, 2, 3],
        'name': '2011-03',
        'review_types': [NORMAL, NORMAL, NORMAL],
        'score': 0.006666666666666666,
        'user': self.userB,
      },
      {
        'issues': [3],
        'latencies': [30],
        'lgtms': [1],
        'name': '2012-04',
        'review_types': [DRIVE_BY],
        'score': 0.3,
        'user': self.userB,
      },
      {
        'issues': [30, 13],
        'latencies': [-1, 1],
        'lgtms': [0, 1],
        'name': '2012-05',
        'review_types': [IGNORED, NORMAL],
        'score': 0.02,
        'user': self.userB,
      },
    ]
    text = 'Stored 3 items\nSkipped 0\n'
    self.trigger_request(self.today, 'monthly', text, expected)

  def test_month_skip(self):
    models.AccountStatsDay(
        id='2011-03-08',
        parent=self.userA_key,
        issues=[1],
        latencies=[1],
        lgtms=[10],
        review_types=[NORMAL],
        modified=self.yesterday).put()
    models.AccountStatsMulti(
        id='2011-03',
        parent=self.userA_key,
        issues=[1],
        latencies=[1],
        lgtms=[10],
        review_types=[NORMAL],
        modified=self.yesterday).put()

    expected = [
      {
        'issues': [1],
        'latencies': [1],
        'lgtms': [10],
        'name': '2011-03',
        'review_types': [NORMAL],
        'score': 0.01,
        'user': self.userA,
      },
    ]
    text = 'Stored 0 items\nSkipped 1\n'
    self.trigger_request(self.today, 'monthly', text, expected)


class TestFetchStats(TestCase):
  def setUp(self):
    super(TestFetchStats, self).setUp()
    user = models.Account.get_account_for_user(User('user@example.com'))
    user_key = user.key
    # Daily.
    models.AccountStatsDay(
        id='2011-03-03',
        parent=user_key,
        issues=[3],
        latencies=[20],
        lgtms=[1],
        review_types=[DRIVE_BY]).put()
    # Month.
    models.AccountStatsMulti(
        id='2011-01',
        parent=user_key,
        issues=[5, 6, 30],
        latencies=[100, 3, 5],
        lgtms=[1, 0, 0],
        review_types=[DRIVE_BY, NORMAL, NORMAL]).put()
    models.AccountStatsMulti(
        id='2011-03',
        parent=user_key,
        issues=[10],
        latencies=[110],
        lgtms=[1],
        review_types=[NOT_REQUESTED]).put()
    # Rolling.
    models.AccountStatsMulti(
        id='30',
        parent=user_key,
        issues=[10, 20],
        latencies=[100, -1],
        lgtms=[1, 0],
        review_types=[NORMAL, IGNORED]).put()

    user = models.Account.get_account_for_user(User('joe@example.com'))
    user_key = user.key
    # Month.
    models.AccountStatsMulti(
        id='2011-02',
        parent=user_key,
        issues=[4, 5],
        latencies=[30, 50],
        lgtms=[1, 0],
        review_types=[NORMAL, NORMAL]).put()
    # Rolling.
    models.AccountStatsMulti(
        id='30',
        parent=user_key,
        issues=[11, 21],
        latencies=[100, 200],
        lgtms=[1, 2],
        review_types=[NORMAL, NORMAL]).put()

    user = models.Account.get_account_for_user(User('john@example.com'))
    user_key = user.key
    # Month.
    models.AccountStatsMulti(
        id='2011-02',
        parent=user_key,
        issues=[8],
        latencies=[-1],
        lgtms=[0],
        review_types=[IGNORED]).put()
    # Rolling.
    models.AccountStatsMulti(
        id='30',
        parent=user_key,
        issues=[11, 21, 34, 35, 36, 37],
        latencies=[100, 200, 10, 10000, 100, 1000],
        lgtms=[1, 2, 0, 0, 0, 0],
        review_types=[NORMAL, NORMAL, NORMAL, NORMAL, NORMAL, NORMAL]).put()

  def assert_json(self, out, expected):
    self.assertEqual(200, out.status_code)
    actual = list(out)
    self.assertEqual(1, len(actual))
    actual = json.loads(actual[0])
    self.assertEqual(expected, actual)

  def trigger_request_show(self, key, expected):
    self.assert_json(
        views.show_user_stats_json(MockRequestGet(), 'user', key),
        expected)

  def trigger_request_leaderboard(self, when, expected):
    self.assert_json(
        views.leaderboard_json(MockRequestGet(), when),
        expected)

  def test_invalid_day(self):
    out = views.show_user_stats_json(MockRequestGet(), 'user', '2012-02-30')
    self.assertEqual(404, out.status_code)

  def test_invalid_month(self):
    out = views.show_user_stats_json(MockRequestGet(), 'user', '2012-13')
    self.assertEqual(404, out.status_code)

  def test_invalid_quarter(self):
    out = views.show_user_stats_json(MockRequestGet(), 'user', '2012-q5')
    self.assertEqual(404, out.status_code)

  def test_invalid_date_future(self):
    out = views.show_user_stats_json(MockRequestGet(), 'user', '3010-01-01')
    self.assertEqual(404, out.status_code)

  def test_not_present_returns_default(self):
    expected = {
      u'issues': [],
      u'latencies': [],
      u'lgtms': [],
      u'name': u'2012-01-01',
      u'review_types': [],
      u'score': models.AccountStatsBase.NULL_SCORE,
    }
    self.trigger_request_show('2012-01-01', expected)

  def test_user_day(self):
    expected = {
      u'issues': [3],
      u'latencies': [20],
      u'lgtms': [1],
      u'name': u'2011-03-03',
      u'review_types': [DRIVE_BY],
      u'score': 0.2,
    }
    self.trigger_request_show('2011-03-03', expected)

  def test_user_month(self):
    expected = {
      u'issues': [5, 6, 30],
      u'latencies': [100, 3, 5],
      u'lgtms': [1, 0, 0],
      u'name': u'2011-01',
      u'review_types': [DRIVE_BY, NORMAL, NORMAL],
      u'score': 0.016666666666666666,
    }
    self.trigger_request_show('2011-01', expected)

  def test_user_quarter(self):
    # Loads up 2011-01 and 2011-03.
    expected = {
      u'issues': [5, 6, 30, 10],
      u'latencies': [100, 3, 5, 110],
      u'lgtms': [1, 0, 0, 1],
      u'name': u'2011-q1',
      u'review_types': [DRIVE_BY, NORMAL, NORMAL, NOT_REQUESTED],
      u'score': 0.13125,
    }
    self.trigger_request_show('2011-Q1', expected)

  def test_user_quarter_empty(self):
    expected = {
      u'issues': [],
      u'latencies': [],
      u'lgtms': [],
      u'name': u'2010-q2',
      u'review_types': [],
      u'score': models.AccountStatsBase.NULL_SCORE,
    }
    self.trigger_request_show('2010-q2', expected)

  def test_user_rolling(self):
    expected = {
      u'issues': [10, 20],
      u'latencies': [100, -1],
      u'lgtms': [1, 0],
      u'name': u'30',
      u'review_types': [NORMAL, IGNORED],
      u'score': 2.0,
    }
    self.trigger_request_show('30', expected)

  def test_leaderboard_json_30(self):
    expected = [
      {
        u'issues': [11, 21, 34, 35, 36, 37],
        u'latencies': [100, 200, 10, 10000, 100, 1000],
        u'lgtms': [1, 2, 0, 0, 0, 0],
        u'name': u'30',
        u'score': 0.25,
        u'review_types': [NORMAL, NORMAL, NORMAL, NORMAL, NORMAL, NORMAL],
        u'user': u'john@example.com',
      },
      {
        u'issues': [11, 21],
        u'latencies': [100, 200],
        u'lgtms': [1, 2],
        u'name': u'30',
        u'score': 0.75,
        u'review_types': [NORMAL, NORMAL],
        u'user': u'joe@example.com',
      },
      {
        u'issues': [10, 20],
        u'latencies': [100, -1],
        u'lgtms': [1, 0],
        u'name': u'30',
        u'score': 2.0,
        u'review_types': [NORMAL, IGNORED],
        u'user': u'user@example.com',
      },
    ]
    self.trigger_request_leaderboard('30', expected)

  def test_leaderboard_json_quarter(self):
    expected = [
      {
        u'issues': [5, 6, 30, 10],
        u'latencies': [100, 3, 5, 110],
        u'lgtms': [1, 0, 0, 1],
        u'name': u'2011-q1',
        u'review_types': [DRIVE_BY, NORMAL, NORMAL, NOT_REQUESTED],
        u'score': 0.13125,
        u'user': u'user@example.com',
      },
      {
        u'issues': [4, 5],
        u'latencies': [30, 50],
        u'lgtms': [1, 0],
        u'name': u'2011-q1',
        u'review_types': [NORMAL, NORMAL],
        u'score': 0.2,
        u'user': u'joe@example.com',
      },
      {
        u'issues': [8],
        u'latencies': [-1],
        u'lgtms': [0],
        u'name': u'2011-q1',
        u'review_types': [IGNORED],
        u'score': models.AccountStatsBase.NULL_SCORE,
        u'user': u'john@example.com',
      },
    ]
    self.trigger_request_leaderboard('2011-Q1', expected)

  def test_leaderboard_quarter(self):
    # Test that there's some html generated.
    out = views.leaderboard(MockRequestGet(), '2011-q1')
    self.assertEqual(200, out.status_code)
    actual = list(out)
    self.assertEqual(1, len(actual))
    # Densify.
    actual = ' '.join(l.strip() for l in actual[0].splitlines())
    expected = (
      '<tr> <td> '
      '<a href="/user/user" onMouseOver="M_showUserInfoPopup(this)">'
      'user</a> </td>')
    self.assertTrue(expected in actual, actual)


class TestProcessIssue(TestCase):
  def setUp(self):
    super(TestProcessIssue, self).setUp()
    now = datetime.datetime.utcnow()
    self.now = datetime.datetime(
        year=now.year, month=now.month, day=now.day, hour=10)
    self.today = self.now.date()
    self.messages = []

    self.owner = 'owner@example.com'
    self.owner_user = User(self.owner)
    self.owner_account = models.Account.get_account_for_user(self.owner_user)

    self.issue = models.Issue(owner=self.owner_user, subject='World domination')
    self.issue.put()

    self.reviewer = 'reviewer@example.com'
    self.reviewer_user = User(self.reviewer)
    self.reviewer_account = models.Account.get_account_for_user(
        self.reviewer_user)
    # Real users have created at least one issue.
    models.Issue(owner=self.reviewer_user, subject='Damned').put()

    self.slacker = 'slacker@example.com'
    self.slacker_user = User(self.slacker)
    self.slacker_account = models.Account.get_account_for_user(
        self.slacker_user)
    # Real users have created at least one issue.
    models.Issue(owner=self.slacker_user, subject='I\'m slacking').put()

    # Sadly mailing lists have accounts too. BUT, these accounts have never
    # created an issue.
    self.ml = 'mailing_list@example.com'
    self.ml_user = User(self.ml)
    self.ml_account = models.Account.get_account_for_user(self.ml_user)

  def add_message(self, sender, recipients, seconds, text):
    """Adds a Message."""
    msg = models.Message(
        parent=self.issue.key,
        issue_key=self.issue.key,
        subject='Your code is great',
        sender=sender,
        recipients=[db.Email(r) for r in recipients],
        date=self.now + datetime.timedelta(seconds=seconds),
        text=text)
    msg.put()
    self.messages.append(msg)

  def process(
      self, who, e_message_index, e_drive_by, e_latency, e_lgtms, r_review):
    people_caches = {'fake':set(), 'real':set()}
    message_index, drive_by = views.search_relevant_first_email_for_user(
        self.owner, self.messages, who, people_caches)
    self.assertEqual(e_message_index, message_index)
    self.assertEqual(e_drive_by, drive_by)
    start = self.messages[message_index].date
    latency, lgtms, review_type = views.process_issue(
        start, self.today, message_index, drive_by, self.owner, self.messages,
        who)
    self.assertEqual(e_latency, latency)
    self.assertEqual(e_lgtms, lgtms)
    self.assertEqual(r_review, review_type)

  def test_mailing_list(self):
    # A user sends an request for review to an mailing list, someone reviews.
    # Use reviewer must not be tagged as drive-by.
    # This is the common case for golang.
    self.add_message(self.owner, [self.ml, self.owner], 10, 'Halp!')
    self.add_message(
        self.reviewer,
        seconds=15,
        recipients=[self.ml, self.owner],
        text='LGTM')
    self.process(self.reviewer, 0, False, 5, 1, NORMAL)

  def test_drive_by(self):
    # Contrary to test_mailing_list, in this one, the author sent the email to
    # at least one human being. This is the common case in Chromium.
    self.add_message(
        self.owner,
        seconds=10,
        recipients=[self.ml, self.owner, self.slacker],
        text='Halp!')
    self.add_message(
        self.reviewer,
        seconds=150,
        recipients=[self.ml, self.owner, self.slacker],
        text='LGTM')
    self.process(self.reviewer, 0, True, 140, 1, DRIVE_BY)

  def test_drive_by_and_mailing_list(self):
    # Combines both; Issue first sent to a mailing list, then someone starts
    # reviewing, then someone else drives-by.
    # For now the second is also considered a normal reviewer. Does it makes
    # sense?
    pass


if __name__ == '__main__':
  if '-v' in sys.argv:
    unittest.TestCase.maxDiff = None
  unittest.main()
