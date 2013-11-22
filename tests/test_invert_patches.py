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

"""Tests for codereview/invert_patches.py."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from codereview import invert_patches


class TestInvertGitPatches(unittest.TestCase):
  """Test the InvertGitPatches class."""

  def setUp(self):
    invert_patches.NULL_FILE_HASH = '0'  # Make it shorter to ease testing.

  def tearDown(self):
    pass

  def test_get_patch_status(self):
    for patch_text, expected_status in (
         # ASCII file patches.
         (self.ADD_PATCH_TEXT, 'A'),
         (self.DELETE_PATCH_TEXT, 'D'),
         (self.MODIFY_PATCH_TEXT_ADD_CHANGES, 'M'),
         (self.CHMOD_PATCH_TEXT_ADD_CHANGES, 'M'),
         (self.COPY_AND_MODIFY_PATCH_TEXT_WITH_NEW_MODE, 'A +'),
         (self.COPY_AND_MODIFY_PATCH_TEXT_WITH_EXISTING_MODE, 'A +'),
         (self.RENAME_AND_MODIFY_PATCH_TEXT_WITH_NEW_MODE, 'A +'),
         (self.RENAME_AND_MODIFY_PATCH_TEXT_WITH_EXISTING_MODE, 'A +'),
         # Bianry file patches.
         (self.ADD_BINARY_PATCH_TEXT, 'A'),
         (self.DELETE_BINARY_PATCH_TEXT, 'D'),
         (self.MODIFY_BINARY_PATCH_TEXT_ADD_CHANGES, 'M'),
         (self.MODIFY_BINARY_PATCH_TEXT_REMOVE_CHANGES, 'M'),
         (self.COPY_AND_MODIFY_BINARY_PATCH_TEXT_WITH_EXISTING_MODE, 'A +'),
         (self.COPY_AND_MODIFY_BINARY_PATCH_TEXT_WITH_NEW_MODE, 'A +'),
         (self.RENAME_AND_MODIFY_BINARY_PATCH_TEXT_WITH_EXISTING_MODE, 'A +'),
         (self.RENAME_AND_MODIFY_BINARY_PATCH_TEXT_WITH_NEW_MODE, 'A +')):
      invert_git_patches = invert_patches.InvertGitPatches(                     
          patch_text, 'dummy_filename')
      self.assertEquals(expected_status, invert_git_patches.status)

  def test_inverted_patch_status(self):
    invert_git_patches = invert_patches.InvertGitPatches(                     
        self.ADD_PATCH_TEXT, 'dummy_filename')
    for original_status, expected_inverted_status in (
        ('M', 'M'), ('dummy_status', 'M'), ('D', 'A'), ('A', 'D'),
        ('A +', 'D')):
      invert_git_patches._status = original_status
      self.assertEquals(expected_inverted_status,
                        invert_git_patches.inverted_patch_status)

  def test_left_and_right_for_inverted_patch(self): 
    headers = 'Index: testfile\ndiff --git a/testfile b/testfile\n'
    for original_status, (expected_left_filename, expected_right_filename) in (
        ('M', ('a/testfile', 'b/testfile')),
        ('dummy_status', ('a/testfile', 'b/testfile')),
        ('D', ('/dev/null', 'b/testfile')),
        ('A', ('a/testfile', '/dev/null')),
        ('A +', ('a/testfile', '/dev/null'))):
      invert_git_patches = invert_patches.InvertGitPatches(
          patch_text=headers,
          filename='testfile')
      invert_git_patches._status = original_status
      (actual_left_filename, actual_right_filename) = (
          invert_git_patches._get_left_and_right_for_inverted_patch())
      self.assertEquals(expected_left_filename, actual_left_filename)
      self.assertEquals(expected_right_filename, actual_right_filename)

  # Patch texts used in the below tests.
  ADD_PATCH_TEXT = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'new file mode 100644\n'
      'index 0..4\n'
      '--- /dev/null\n'
      '+++ b/file100\n'
      '@@ -0,0 +1,3 @@\n'
      '+test++')
  DELETE_PATCH_TEXT = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'deleted file mode 100644\n'
      'index 4..0\n'
      '--- a/file100\n'
      '+++ /dev/null\n'
      '@@ -1,3 +0,0 @@\n'
      '-test--')
  MODIFY_PATCH_TEXT_ADD_CHANGES = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'index 4..5 100644\n'
      '--- a/file100\n'
      '+++ b/file100\n'
      '@@ -1,3 +1,4 @@\n'
      '-+test')
  MODIFY_PATCH_TEXT_REMOVE_CHANGES = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'index 5..4 100644\n'
      '--- a/file100\n'
      '+++ b/file100\n'
      '@@ -1,4 +1,4 @@\n'
      '-test   +')
  CHMOD_PATCH_TEXT_ADD_CHANGES = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'old mode 100644\n'
      'new mode 100755')
  CHMOD_PATCH_TEXT_REMOVE_CHANGES = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'old mode 100755\n'
      'new mode 100644')
  COPY_AND_MODIFY_PATCH_TEXT_WITH_NEW_MODE = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'old mode 100755\n'
      'new mode 100644\n'
      'similarity index 77%\n'
      'copy from file1\n'
      'copy to file100\n'
      'index 5..4\n'
      '--- a/file1\n'
      '+++ b/file100\n'
      '@@ -1,3 +1,3 @@\n'
      '-+test')
  COPY_AND_MODIFY_PATCH_TEXT_WITH_EXISTING_MODE = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'similarity index 77%\n'
      'copy from file1\n'
      'copy to file100\n'
      'index 5..4 100644\n'
      '--- a/file1\n'
      '+++ b/file100\n'
      '@@ -1,3 +1,3 @@\n'
      '-+test')
  RENAME_AND_MODIFY_PATCH_TEXT_WITH_NEW_MODE = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'old mode 100755\n'
      'new mode 100644\n'
      'similarity index 77%\n'
      'rename from file1\n'
      'rename to file100\n'
      'index 5..4\n'
      '--- a/file1\n'
      '+++ b/file100\n'
      '@@ -1,3 +1,3 @@\n'
      '-+test')
  RENAME_AND_MODIFY_PATCH_TEXT_WITH_EXISTING_MODE = (
      'Index: file100\n'
      'diff --git a/file100 b/file100\n'
      'similarity index 77%\n'
      'rename from file1\n'
      'rename to file100\n'
      'index 5..4 100644\n'
      '--- a/file1\n'
      '+++ b/file100\n'
      '@@ -1,3 +1,3 @@\n'
      '-+test')
  SVN_PATCH_TEXT = (
      'Index: file100\n'
      '==============\n'
      '--- file100 (revision 111)\n'
      '+++ file100 (working copy)\n'
      '@@ -1,3 +1,3 @@\n'
      '-+test')

  def test_get_inverted_patch_for_add(self):
    lines = ['test', '', '']
    patched_lines = []
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.ADD_PATCH_TEXT,
        filename='file100')

    self.assertEquals(self.DELETE_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_delete(self):
    lines = []
    patched_lines = ['test', '', '']
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.DELETE_PATCH_TEXT,
        filename='file100')

    self.assertEquals(self.ADD_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_modify(self):
    lines = ['test', '', '', '']
    patched_lines = ['', '', '', '']
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.MODIFY_PATCH_TEXT_ADD_CHANGES,
        filename='file100')

    self.assertEquals(self.MODIFY_PATCH_TEXT_REMOVE_CHANGES,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_chmod(self):
    lines = ['test', '', '', '']
    patched_lines = ['test', '', '', '']
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.CHMOD_PATCH_TEXT_ADD_CHANGES,
        filename='file100')

    self.assertEquals(self.CHMOD_PATCH_TEXT_REMOVE_CHANGES,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_copy_and_modify_with_new_mode(self):
    lines = ['test', '', '']
    patched_lines = []
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.COPY_AND_MODIFY_PATCH_TEXT_WITH_NEW_MODE,
        filename='file100')

    self.assertEquals(self.DELETE_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_copy_and_modify_with_existing_mode(self):
    lines = ['test', '', '']
    patched_lines = []
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.COPY_AND_MODIFY_PATCH_TEXT_WITH_EXISTING_MODE,
        filename='file100')

    self.assertEquals(self.DELETE_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_rename_and_modify_with_new_mode(self):
    lines = ['test', '', '']
    patched_lines = []
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.RENAME_AND_MODIFY_PATCH_TEXT_WITH_NEW_MODE,
        filename='file100')

    self.assertEquals(self.DELETE_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_rename_and_modify_with_existing_mode(self):
    lines = ['test', '', '']
    patched_lines = []
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.RENAME_AND_MODIFY_PATCH_TEXT_WITH_EXISTING_MODE,
        filename='file100')

    self.assertEquals(self.DELETE_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text(
                          lines, patched_lines))

  def test_get_inverted_patch_for_svn_failure(self):
    try:
      invert_git_patches = invert_patches.InvertGitPatches(
          patch_text=self.SVN_PATCH_TEXT,
          filename='file100')
      self.fail('Expected failure due to unsupported SVN patch.')
    except AssertionError, e:
      # Expected.
      self.assertEquals('Not a Git patch', e.message)

  # Binary patch texts used in the below tests.
  ADD_BINARY_PATCH_TEXT = (
      'Index: img/file.png\n'
      'diff --git a/img/file.png b/img/file.png\n'
      'new file mode 100644\n'
      'index 0..4\n'
      'Binary files /dev/null and b/img/file.png differ')
  DELETE_BINARY_PATCH_TEXT = (
      'Index: img/file.png\n'
      'diff --git a/img/file.png b/img/file.png\n'
      'deleted file mode 100644\n'
      'index 4..0\n'
      'Binary files a/img/file.png and /dev/null differ')
  MODIFY_BINARY_PATCH_TEXT_ADD_CHANGES = (
      'Index: img/file.png\n'
      'diff --git a/img/file.png b/img/file.png\n'
      'index 4..5 100644\n'
      'Binary files a/img/file.png and b/img/file.png differ')
  MODIFY_BINARY_PATCH_TEXT_REMOVE_CHANGES = (
      'Index: img/file.png\n'
      'diff --git a/img/file.png b/img/file.png\n'
      'index 5..4 100644\n'
      'Binary files a/img/file.png and b/img/file.png differ')
  COPY_AND_MODIFY_BINARY_PATCH_TEXT_WITH_EXISTING_MODE = (
      'Index: img/file.png\n'
      'diff --git a/img/old.png b/img/file.png\n'
      'similarity index 99%\n'
      'copy from img/old.png\n'
      'copy to img/file.png\n'
      'index 5..4 100644\n'
      'Binary files a/img/old.png and b/img/file.png differ')
  COPY_AND_MODIFY_BINARY_PATCH_TEXT_WITH_NEW_MODE = (
      'Index: img/file.png\n'
      'diff --git a/img/old.png b/img/file.png\n'
      'old mode 100755\n'
      'new mode 100644\n'
      'similarity index 99%\n'
      'copy from img/old.png\n'
      'copy to img/file.png\n'
      'index 5..4\n'
      'Binary files a/img/old.png and b/img/file.png differ')
  RENAME_AND_MODIFY_BINARY_PATCH_TEXT_WITH_EXISTING_MODE = (
      'Index: img/file.png\n'
      'diff --git a/img/old.png b/img/file.png\n'
      'similarity index 99%\n'
      'rename from img/old.png\n'
      'rename to img/file.png\n'
      'index 5..4 100644\n'
      'Binary files a/img/old.png and b/img/file.png differ')
  RENAME_AND_MODIFY_BINARY_PATCH_TEXT_WITH_NEW_MODE = (
      'Index: img/file.png\n'
      'diff --git a/img/old.png b/img/file.png\n'
      'old mode 100755\n'
      'new mode 100644\n'
      'similarity index 99%\n'
      'rename from img/old.png\n'
      'rename to img/file.png\n'
      'index 5..4\n'
      'Binary files a/img/old.png and b/img/file.png differ')

  def test_get_inverted_patch_for_binary_add(self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.ADD_BINARY_PATCH_TEXT,
        filename='img/file.png')
    self.assertEquals(self.DELETE_BINARY_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text([], []))

  def test_get_inverted_patch_for_binary_delete(self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.DELETE_BINARY_PATCH_TEXT,
        filename='img/file.png')
    self.assertEquals(self.ADD_BINARY_PATCH_TEXT,
                      invert_git_patches.get_inverted_patch_text([], []))

  def test_get_inverted_patch_for_binary_modify(self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.MODIFY_BINARY_PATCH_TEXT_ADD_CHANGES,
        filename='img/file.png')
    self.assertEquals(self.MODIFY_BINARY_PATCH_TEXT_REMOVE_CHANGES,
                      invert_git_patches.get_inverted_patch_text([], []))

  def test_get_inverted_patch_for_binary_copy_and_modify_with_existing_mode(
      self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.COPY_AND_MODIFY_BINARY_PATCH_TEXT_WITH_EXISTING_MODE,
        filename='img/file.png')
    self.assertEquals(self.DELETE_BINARY_PATCH_TEXT + '\n',
                      invert_git_patches.get_inverted_patch_text([], []))

  def test_get_inverted_patch_for_binary_copy_and_modify_with_new_mode(self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.COPY_AND_MODIFY_BINARY_PATCH_TEXT_WITH_NEW_MODE,
        filename='img/file.png')
    self.assertEquals(self.DELETE_BINARY_PATCH_TEXT + '\n',
                      invert_git_patches.get_inverted_patch_text([], []))

  def test_get_inverted_patch_for_binary_rename_and_modify_with_existing_mode(
      self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.RENAME_AND_MODIFY_BINARY_PATCH_TEXT_WITH_EXISTING_MODE,
        filename='img/file.png')
    self.assertEquals(self.DELETE_BINARY_PATCH_TEXT + '\n',
                      invert_git_patches.get_inverted_patch_text([], []))

  def test_get_inverted_patch_for_binary_rename_and_modify_with_new_mode(self):
    invert_git_patches = invert_patches.InvertGitPatches(
        patch_text=self.RENAME_AND_MODIFY_BINARY_PATCH_TEXT_WITH_NEW_MODE,
        filename='img/file.png')
    self.assertEquals(self.DELETE_BINARY_PATCH_TEXT + '\n',
                      invert_git_patches.get_inverted_patch_text([], []))


if __name__ == '__main__':
  unittest.main()
