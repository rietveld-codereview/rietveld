# Copyright 2012 Google Inc.
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

"""Tests for models functions and helpers."""

from codereview.models import Issue

from utils import TestCase


class TestCollaboratorEmailsFromDescription(TestCase):
  """Test the Issue._collaborator_emails_from_description function."""

  def test_no_collaborator(self):
    description = 'Hello!\n\nBUG=12345'
    self.assertEqual(
        [], Issue._collaborator_emails_from_description(description))

  def test_not_an_email_address(self):
    descriptions = [
        'Howdie!\n\nCOLLABORATOR=joi\nBUG=12345',
        'Howdie!\n\nCOLLABORATOR=joi@google\nBUG=12345',
    ]
    for description in descriptions:
      self.assertEqual(
        [], Issue._collaborator_emails_from_description(description))

  def test_one_valid_collaborator(self):
    descriptions = [
        'Howdie!\n\nCOLLABORATOR=joi@chromium.org\nBUG=12345',
        'Howdie!\n\nCOLLABORATOR=joi@chromium.org \nBUG=12345',
        'Howdie!\n\n COLLABORATOR =\tjoi@chromium.org \nBUG=12345',
        'Howdie!\nCOLLABORATOR = joi@chromium.org \nCOLLABORATOR=smurf',
    ]
    for description in descriptions:
      self.assertEqual(
          ['joi@chromium.org'],
          Issue._collaborator_emails_from_description(description))

  def test_multiple_collaborators(self):
    collaborators = Issue._collaborator_emails_from_description(
        'Hello world!\nCOLLABORATOR=one@one.com\nCOLLABORATOR=two@two.com')
    self.assertEqual(['one@one.com', 'two@two.com'], collaborators)
