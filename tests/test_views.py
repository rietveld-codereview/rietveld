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

from django.http import HttpRequest

from google.appengine.api.users import User
from google.appengine.ext import db

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
        self.ps = models.PatchSet(parent=self.issue, issue=self.issue)
        self.ps.data = load_file('ps1.diff')
        self.ps.save()
        self.patches = engine.ParsePatchSet(self.ps)
        db.put(self.patches)

    def test_draft_details_no_base_file(self):
        request = MockRequest(User('foo@example.com'), issue=self.issue)
        # add a comment and render
        cmt1 = models.Comment(patch=self.patches[0], parent=self.patches[0])
        cmt1.text = 'test comment'
        cmt1.lineno = 1
        cmt1.left = False
        cmt1.draft = True
        cmt1.author = self.user
        cmt1.save()
        # Add a second comment
        cmt2 = models.Comment(patch=self.patches[1], parent=self.patches[1])
        cmt2.text = 'test comment 2'
        cmt2.lineno = 2
        cmt2.left = False
        cmt2.draft = True
        cmt2.author = self.user
        cmt2.save()
        # Add fake content
        content1 = models.Content(text="foo\nbar\nbaz\nline\n")
        content1.put()
        content2 = models.Content(text="foo\nbar\nbaz\nline\n")
        content2.put()
        cmt1.patch.content = content1
        cmt1.patch.put()
        cmt2.patch.content = content2
        cmt2.patch.put()
        # Mock get content calls. The first fails with an FetchError,
        # the second succeeds (see issue384).
        def raise_err():
            raise models.FetchError()
        cmt1.patch.get_content = raise_err
        cmt2.patch.get_patched_content = lambda: content2
        tbd, comments = views._get_draft_comments(request, self.issue)
        self.assertEqual(len(comments), 2)
        # Try to render draft details using the patched Comment
        # instances from here.
        views._get_draft_details(request, [cmt1, cmt2])
