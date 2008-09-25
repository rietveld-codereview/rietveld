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

"""Tests for Rietveld."""

import os

from django.test import TestCase

from google.appengine.api import users
from google.appengine.ext import db

import engine
import models

# Set some essential variables.
# TODO(guido): Shouldn't InstallAppengineHelperForDjango() do this?
os.environ['SERVER_NAME'] = 'localhost'
os.environ['SERVER_PORT'] = '80'
os.environ['USER_EMAIL'] = ''

# Install a mock.
engine.FetchBase = lambda base, patch: models.Content(text=db.Text('foo'))


class BaseTest(TestCase):

  def setUp(self):
    self._me = users.User(email='me@example.com')
    self._me.account = models.Account.get_account_for_user(self._me)
    self._you = users.User(email='you@example.com')
    self._you.account = models.Account.get_account_for_user(self._you)


# Model tests


class IssueTest(BaseTest):

  def test_createIssue(self):
    i1 = models.Issue(subject='x', owner=self._me)
    i1.put()
    self.assertEqual(models.Issue.get_by_id(i1.key().id()), i1)

  def test_draft_comment_visibility(self):
    i1 = models.Issue(subject='x', owner=self._me)
    i1.put()
    self.assertEqual(i1.num_comments, 0)
    self.assertEqual(i1.num_drafts, 0)
    # Add some draft comments, in the proper hierarchy:
    ps1 = models.PatchSet(owner=self._me, parent=i1)
    ps1.put()
    p1 = models.Patch(owner=self._me, parent=ps1)
    p1.put()
    c1 = models.Comment(draft=True, author=self._me, parent=p1)
    c1.put()
    c2 = models.Comment(draft=True, author=self._me, parent=p1)
    c2.put()
    c3 = models.Comment(draft=True, author=self._you, parent=p1)
    c3.put()
    # From anonymous perspective:
    models.Account.current_user_account = None
    i1.n_comments = i1._num_drafts = None # reset caches
    self.assertEqual(i1.num_comments, 0)
    self.assertEqual(i1.num_drafts, 0)
    # From my perspective:
    models.Account.current_user_account = self._me.account
    i1.n_comments = i1._num_drafts = None # reset caches
    self.assertEqual(i1.num_comments, 0)
    self.assertEqual(i1.num_drafts, 2)
    # From your perspective:
    models.Account.current_user_account = self._you.account
    i1.n_comments = i1._num_drafts = None # reset caches
    self.assertEqual(i1.num_comments, 0)
    self.assertEqual(i1.num_drafts, 1)
    # Submit some drafts:
    c1.draft = False
    c1.put()
    c2.draft = False
    c2.put()
    # From anonymous perspective:
    models.Account.current_user_account = None
    i1.n_comments = i1._num_drafts = None # reset caches
    self.assertEqual(i1.num_comments, 2)
    self.assertEqual(i1.num_drafts, 0)
    # From my perspective:
    models.Account.current_user_account = self._me.account
    i1.n_comments = i1._num_drafts = None # reset caches
    self.assertEqual(i1.num_comments, 2)
    self.assertEqual(i1.num_drafts, 0)
    # From your perspective:
    models.Account.current_user_account = self._you.account
    i1.n_comments = i1._num_drafts = None # reset caches
    self.assertEqual(i1.num_comments, 2)
    self.assertEqual(i1.num_drafts, 1)


class ContentTest(BaseTest):

  def test_lines(self):
    c1 = models.Content()
    self.assertEqual(c1.lines, [])
    c1.text = db.Text()
    self.assertEqual(c1.lines, [])
    c1.text = db.Text('foo\nbar')
    self.assertEqual(c1.lines, [u'foo\n', u'bar'])
    self.assertEqual(c1.lines[0], u'foo\n')
    self.assert_(isinstance(c1.lines[0], unicode))


class PatchTest(BaseTest):

  def test_basic(self):
    i1 = models.Issue(base=db.Link('http://python.org'), subject='x',
                      owner=self._me)
    i1.put()
    ps1 = models.PatchSet(parent=i1, issue=i1, owner=self._me)
    ps1.put()
    p1 = models.Patch(parent=ps1, patchset=ps1)
    self.assertEqual(p1.content, None)
    p1._content = db.Key.from_path('Content', 42)  # Doesn't exist
    p1._patched_content = db.Key.from_path('Content', 42)  # Ditto
    self.assertRaises(db.Error, lambda : p1.content)
    self.assertEqual(p1.get_content().text, u'foo')
    self.assertEqual(p1.content.text, u'foo')
    self.assertRaises(db.Error, lambda : p1.patched_content)
    self.assertEqual(p1.get_patched_content().text, u'foo')
    self.assertEqual(p1.patched_content.text, u'foo')


class CommentText(BaseTest):

  def test_basic(self):
    c1 = models.Comment(draft=False, text='  woo'*13)
    c1.complete(models.Patch())
    self.assertEqual(c1.shorttext,
                     u'woo  woo  woo  woo  woo  woo  woo  woo  woo  woo')
    self.assertEqual(len(c1.buckets), 1)
    self.assertEqual(c1.buckets[0].text,
                     (u'  woo  woo  woo  woo  woo  woo  woo  woo'
                      u'  woo  woo  woo  woo  woo'))


# View tests

class ViewIndexTest(BaseTest):

  def test_basic(self):
    r = self.client.get('/')
    self.assertEqual(r.status_code, 200)
    self.assertEqual(r.content.splitlines()[0],
                     ('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 '
                      'Transitional//EN"'))
    r = self.client.get('/bogus')
    self.assertEqual(r.status_code, 404)
    r = self.client.get('/mine')
    self.assertEqual(r.status_code, 302)
    self.assert_('location' in r._headers)
    self.assertEqual(r._headers['location'][0], 'Location')
    self.assertEqual(r._headers['location'][1],
                     ('http://testserver/_ah/login?'
                      'continue=http%3A//localhost/mine'))
