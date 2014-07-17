#!/usr/bin/env python
# Copyright 2011 Google Inc.
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

"""Tests for view functions and helpers."""

import datetime
import json
import unittest

import setup
setup.process_args()


from django.http import HttpRequest

from google.appengine.api.users import User
from google.appengine.ext import ndb

from utils import TestCase, load_file

from codereview import models, views
from codereview import engine  # engine must be imported after models :(


class MockRequest(HttpRequest):
    """Mock request class for testing."""

    def __init__(self, user=None, issue=None):
        super(MockRequest, self).__init__()
        self.META['HTTP_HOST'] = 'testserver'
        self.user = user
        self.issue = issue


class TestPublish(TestCase):
    """Test publish functions."""

    def setUp(self):
        super(TestPublish, self).setUp()
        self.user = User('foo@example.com')
        self.login('foo@example.com')
        self.issue = models.Issue(subject='test')
        self.issue.local_base = False
        self.issue.put()
        self.ps = models.PatchSet(parent=self.issue.key, issue_key=self.issue.key)
        self.ps.data = load_file('ps1.diff')
        self.ps.put()
        self.patches = engine.ParsePatchSet(self.ps)
        ndb.put_multi(self.patches)

    def test_draft_details_no_base_file(self):
        request = MockRequest(User('foo@example.com'), issue=self.issue)
        # add a comment and render
        cmt1 = models.Comment(
            patch_key=self.patches[0].key, parent=self.patches[0].key)
        cmt1.text = 'test comment'
        cmt1.lineno = 1
        cmt1.left = False
        cmt1.draft = True
        cmt1.author = self.user
        cmt1.put()
        # Add a second comment
        cmt2 = models.Comment(
            patch_key=self.patches[1].key, parent=self.patches[1].key)
        cmt2.text = 'test comment 2'
        cmt2.lineno = 2
        cmt2.left = False
        cmt2.draft = True
        cmt2.author = self.user
        cmt2.put()
        # Add fake content
        content1 = models.Content(text="foo\nbar\nbaz\nline\n")
        content1.put()
        content2 = models.Content(text="foo\nbar\nbaz\nline\n")
        content2.put()
        cmt1_patch = cmt1.patch_key.get()
        cmt1_patch.content_key = content1.key
        cmt1_patch.put()
        cmt2_patch = cmt2.patch_key.get()
        cmt2_patch.content_key = content2.key
        cmt2_patch.put()
        # Mock get content calls. The first fails with an FetchError,
        # the second succeeds (see issue384).
        def raise_err():
            raise models.FetchError()
        cmt1.patch_key.get().get_content = raise_err
        cmt2.patch_key.get().get_patched_content = lambda: content2
        tbd, comments = views._get_draft_comments(request, self.issue)
        self.assertEqual(len(comments), 2)
        # Try to render draft details using the patched Comment
        # instances from here.
        views._get_draft_details(request, [cmt1, cmt2])


class TestSearch(TestCase):

    def setUp(self):
        """Create two test issues and users."""
        super(TestSearch, self).setUp()
        user = User('bar@example.com')
        models.Account.get_account_for_user(user)
        user = User('test@groups.example.com')
        models.Account.get_account_for_user(user)
        self.user = User('foo@example.com')
        self.login('foo@example.com')
        issue1 = models.Issue(subject='test')
        issue1.reviewers = ['test@groups.example.com',
                            'bar@example.com']
        issue1.local_base = False
        issue1.put()
        issue2 = models.Issue(subject='test')
        issue2.reviewers = ['test2@groups.example.com',
                            'bar@example.com']
        issue2.local_base = False
        issue2.put()

    def test_json_get_api(self):
        today = datetime.date.today()
        start = datetime.datetime(today.year, today.month, 1)
        next_month = today + datetime.timedelta(days=31)
        end = datetime.datetime(next_month.year, next_month.month, 1)
        # This search is derived from a real query that comes up in the logs
        # quite regulary. It searches for open issues with a test group as
        # reviewer within a month and requests the returned data to be encoded
        # as JSON.
        response = self.client.get('/search', {
            'closed': 3, 'reviewer': 'test@groups.example.com',
            'private': 1, 'created_before': str(end),
            'created_after': str(start), 'order': 'created',
            'keys_only': False, 'with_messages': False, 'cursor': '',
            'limit': 1000, 'format': 'json'
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'],
                         'application/json; charset=utf-8')
        payload = json.loads(response.content)
        self.assertEqual(len(payload['results']), 1)


class TestModifierCount(TestCase):
    """Test modifier counts for the latest patchset."""

    def line_count(self, lines):
        if lines == 1:
            return ''
        return ",%d", lines

    def makePatch(self, add_lines, remove_lines):
        patch = (
            "Index: cc/layers/layer.cc\n"
            "==============================="
            "====================================\n"
            "--- a/cc/layers/layer.cc\n"
            "+++ b/cc/layers/layer.cc\n"
            "@@ -905%s +904%s @@"
            " void Layer::PushPropertiesTo(LayerImpl* layer) {\n") % (
            (self.line_count(add_lines),
             self.line_count(remove_lines)))
        for i in range(0, remove_lines):
            patch += "-base::Passed(&original_request)));\n"
        for i in range(0, add_lines):
            patch += "+base::Passed(&new_request)));\n"

        return patch

    def setUp(self):
        super(TestModifierCount, self).setUp()
        self.user = User('foo@example.com')
        self.login('foo@example.com')

    def test_empty_patch(self):
        issue = models.Issue(subject="test with 0 lines")
        issue.local_base = False
        issue.put()
        added, removed = views._get_modified_counts(issue)
        self.assertEqual(0, added)
        self.assertEqual(0, removed)

    def test_add_patch(self):
        issue = models.Issue(subject="test with 1 line removed")
        issue.local_base = False
        issue.put()
        ps = models.PatchSet(parent=issue.key, issue_key=issue.key)
        ps.data = self.makePatch(1, 0)
        ps.put()
        patches = engine.ParsePatchSet(ps)
        ndb.put_multi(patches)
        added, removed = views._get_modified_counts(issue)
        self.assertEqual(1, added)
        self.assertEqual(0, removed)

    def test_remove_patch(self):
        issue = models.Issue(subject="test with 1 line removed")
        issue.local_base = False
        issue.put()
        ps = models.PatchSet(parent=issue.key, issue_key=issue.key)
        ps.data = self.makePatch(0, 1)
        ps.put()
        patches = engine.ParsePatchSet(ps)
        ndb.put_multi(patches)
        added, removed = views._get_modified_counts(issue)
        self.assertEqual(0, added)
        self.assertEqual(1, removed)

    def test_both_patch(self):
        issue = models.Issue(subject="test with changes")
        issue.local_base = False
        issue.put()
        ps = models.PatchSet(parent=issue.key, issue_key=issue.key)
        ps.data = self.makePatch(5, 7)
        ps.put()
        patches = engine.ParsePatchSet(ps)
        ndb.put_multi(patches)
        added, removed = views._get_modified_counts(issue)
        self.assertEqual(5, added)
        self.assertEqual(7, removed)


if __name__ == '__main__':
  unittest.main()
