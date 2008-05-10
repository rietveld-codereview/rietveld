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

__test__ = {

    'models.Issue': r"""

    Prepare:

    >>> from models import *
    >>> me = users.User(email='me@gmail.com')
    >>> you = users.User(email='you@gmail.com')
    >>>

    Basic test:

    >>> i1 = Issue(subject='x', owner=me)
    >>> _ = i1.put()
    >>> i1.num_comments
    0
    >>> i1.num_drafts
    0
    >>>

    Add some draft comments, in the proper hierarchy:

    >>> ps1 = PatchSet(owner=me, parent=i1)
    >>> _ = ps1.put()
    >>> p1 = Patch(owner=me, parent=ps1)
    >>> _ = p1.put()
    >>> c1 = Comment(draft=True, author=me, parent=p1)
    >>> _ = c1.put()
    >>> c2 = Comment(draft=True, author=me, parent=p1)
    >>> _ = c2.put()
    >>> c3 = Comment(draft=True, author=you, parent=p1)
    >>> _ = c3.put()
    >>>

    From anonymous perspective:

    >>> os.environ['USER_EMAIL'] = ''
    >>> i1._num_comments = i1._num_drafts = None  # reset caches
    >>> i1.num_comments
    0
    >>> i1.num_drafts
    0
    >>>

    From my perspective:

    >>> os.environ['USER_EMAIL'] = 'me@gmail.com'
    >>> i1._num_comments = i1._num_drafts = None  # reset caches
    >>> i1.num_comments
    0
    >>> i1.num_drafts
    2
    >>>

    From your perspective:

    >>> os.environ['USER_EMAIL'] = 'you@gmail.com'
    >>> i1._num_comments = i1._num_drafts = None  # reset caches
    >>> i1.num_comments
    0
    >>> i1.num_drafts
    1
    >>>

    Submit some drafts:

    >>> c1.draft = False
    >>> _ = c1.put()
    >>> c2.draft = False
    >>> _ = c2.put()
    >>>

    From anonymous perspective:

    >>> os.environ['USER_EMAIL'] = ''
    >>> i1._num_comments = i1._num_drafts = None  # reset caches
    >>> i1.num_comments
    2
    >>> i1.num_drafts
    0
    >>>

    From my perspective:

    >>> os.environ['USER_EMAIL'] = 'me@gmail.com'
    >>> i1._num_comments = i1._num_drafts = None  # reset caches
    >>> i1.num_comments
    2
    >>> i1.num_drafts
    0
    >>>

    From your perspective:

    >>> os.environ['USER_EMAIL'] = 'you@gmail.com'
    >>> i1._num_comments = i1._num_drafts = None  # reset caches
    >>> i1.num_comments
    2
    >>> i1.num_drafts
    1
    >>>

    """,

    'models.Content': r"""

    >>> from models import *
    >>> c1 = Content()
    >>> c1.lines
    []
    >>> c1.text = db.Text()
    >>> c1.lines
    []
    >>> c1.text = db.Text('foo\nbar')
    >>> c1.lines
    [u'foo\n', u'bar']
    >>>

    """,

    'models.Patch': r"""

    >>> os.environ['USER_EMAIL'] = ''
    >>> from models import *
    >>> me = users.User(email='me@gmail.com')
    >>> you = users.User(email='you@gmail.com')
    >>>

    >>> i1 = Issue(base=db.Link('http://python.org'), subject='x', owner=me)
    >>> _ = i1.put()
    >>> ps1 = PatchSet(parent=i1, issue=i1, owner=me)
    >>> _ = ps1.put()
    >>> p1 = Patch(parent=ps1, patchset=ps1)
    >>> print p1.content
    None
    >>> p1._content = db.Key.from_path('Content', 42)  # Doesn't exist
    >>> p1._patched_content = db.Key.from_path('Content', 42)  # Ditto
    >>> p1.content
    Traceback (most recent call last):
        ...
    Error: ReferenceProperty failed to be resolved
    >>> p1.get_content().text
    u'foo'
    >>> p1.content.text
    u'foo'
    >>> p1.patched_content
    Traceback (most recent call last):
        ...
    Error: ReferenceProperty failed to be resolved
    >>> p1.get_patched_content().text
    u'foo'
    >>> p1.patched_content.text
    u'foo'
    >>>

    """,

    'models.Comment': r"""

    >>> from models import *
    >>> c1 = Comment(draft=False, text='  woo'*13)
    >>> c1.complete(Patch())
    >>> c1.shorttext
    u'woo  woo  woo  woo  woo  woo  woo  woo  woo  woo'
    >>> len(c1.buckets)
    1
    >>> c1.buckets[0].text
    u'  woo  woo  woo  woo  woo  woo  woo  woo  woo  woo  woo  woo  woo'
    >>>

    """,

    'views.index': r"""

    >>> import os
    >>> from django.test.client import Client
    >>> c = Client()
    >>> r = c.get('/')
    >>> r.status_code
    200
    >>> r.content.splitlines()[0]
    '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"'
    >>> r = c.get('/bogus')
    >>> r.status_code
    404
    >>> r = c.get('/mine')
    >>> r.status_code
    302
    >>> r._headers['location']
    ('Location', 'http://testserver/_ah/login?continue=http%3A//localhost/mine')
    >>>

    """,

    }
