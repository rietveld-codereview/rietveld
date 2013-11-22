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

"""Contains utilities to invert a patch."""

import difflib
import os
import re
import sys


# Listing of supported patch statuses.
ADDED_STATUS = 'A'
COPIED_AND_MODIFIED_STATUS = 'A +'
DELETED_STATUS = 'D'
MODIFIED_STATUS = 'M'

# Null file constants.
NULL_FILE = '/dev/null'
NULL_FILE_HASH = '0000000000000000000000000000000000000000'


def is_git_diff_header(diff_header):
  """Returns True if the diff was generated with git."""
  return any(l.startswith('diff --git') for l in diff_header.splitlines())


def split_header(diff):                                                      
  """Splits a diff in two: the header and the chunks."""                      
  header = []                                                                 
  chunks = diff.splitlines(True)                                              
  while chunks:                                                               
    if chunks[0].startswith('--- '):                                          
      break                                                                   
    header.append(chunks.pop(0))                                              
  else:                                                                       
    # Some diff may not have a ---/+++ set like a git rename with no change or
    # a permissions change.                                                   
    pass                                                                      

  if chunks:                                                                  
    assert chunks[0].startswith('--- '), 'Inconsistent header'                
  return ''.join(header), ''.join(chunks)      


class InvertGitPatches(object):
  """Utility to invert a Git patch.

  Follows the diff behavior in
  https://www.kernel.org/pub/software/scm/git/docs/git-diff.html
  """

  def __init__(self, patch_text, filename):
    """Creates an InvertGitPatches instance.

    Args:
      patch_text: (str) Contains the diff text of the patch we want to invert.
      filename: (str) The file the patch applies to.
    """
    self._filename = filename
    self._diff_header, unused_diff_chunks = split_header(patch_text)
    # Make sure it is a git patch.
    assert is_git_diff_header(self._diff_header), 'Not a Git patch'
    self._status = self.get_patch_status(self._diff_header)

  @staticmethod
  def get_patch_status(diff_header):
    """Parses the header to figure out what kind of patch it is.

    Returns the status of the patch (A/A+/D/M).
    """
    index_match =  re.search(r"(?m)^index ([a-z0-9]+)\.\.([a-z0-9]+)",
                             diff_header)
    if index_match:
      left_index = index_match.group(1)
      right_index = index_match.group(2)
      if left_index == NULL_FILE_HASH:
        # 'A' patch will have the null file in the left index.
        return ADDED_STATUS
      elif right_index == NULL_FILE_HASH:
        # 'D' patch will have the null file in the right index.
        return DELETED_STATUS
      else:
        # Look for 'copy/rename from' and 'copy/rename to' for 'A +' patches.
        if (re.search(r"(?m)^(copy|rename) from ", diff_header)
            and re.search(r"(?m)^(copy|rename) to ", diff_header)):
          return COPIED_AND_MODIFIED_STATUS
    # Assume 'M' for everything else.
    return MODIFIED_STATUS

  @property
  def status(self):
    return self._status

  @property
  def inverted_patch_status(self):
    """Returns the inverse of the original status."""
    if self._status == MODIFIED_STATUS:
      # Modifications will remain modifications.
      inverted_status = self._status
    elif self._status == DELETED_STATUS:
      # Deletions will now be additions.
      inverted_status = ADDED_STATUS
    elif (self._status == ADDED_STATUS or
          self._status == COPIED_AND_MODIFIED_STATUS):
      # Additions will now be deletions.
      inverted_status = DELETED_STATUS
    else:
      # Everything else will be treated as a modification.
      inverted_status = MODIFIED_STATUS
    return inverted_status

  def get_inverted_patch_text(self, lines, patched_lines):
    """Inverts the text of the patch."""
    inverted_header = self._get_inverted_header()
    (left_file, right_file) = self._get_left_and_right_for_inverted_patch()
    inverted_chunk =  ''.join(difflib.unified_diff(lines,
                                                   patched_lines,
                                                   fromfile=left_file,
                                                   tofile=right_file))
    inverted_patch_text = inverted_header + inverted_chunk
    return inverted_patch_text

  def _get_left_and_right_for_inverted_patch(self):
    """Parses the patch text to find the left and right files for inversion.

    Returns a tuple of (left_filename, right_filename).
    """
    filenames_match = re.search(r"(?m)^diff --git (.+?) (.+?)\n",
                                self._diff_header)
    left_filename = filenames_match.group(1)
    right_filename = filenames_match.group(2)
    if self._status == COPIED_AND_MODIFIED_STATUS:
      # 'A +' has the file it is copied from on the left, we instead want
      # to use the filename that will be deleted.
      left_filename = 'a/%s' % self._filename
      right_filename = NULL_FILE
    elif self._status == ADDED_STATUS:
      right_filename = NULL_FILE
    elif self._status == DELETED_STATUS:
      left_filename = NULL_FILE
    return (left_filename, right_filename)

  def _get_inverted_header(self):
    """Inverts the header of the patch."""

    # Start off with the original header and invert in place.
    inverted_header = self._diff_header

    # All inverse patches need the git index header reversed.
    index_match =  re.search(
        r"(?m)^index ([a-z0-9]+)\.\.([a-z0-9]+) ?([0-9]+)?",
        self._diff_header)
    if index_match:
      inverted_index = 'index %s..%s' % (index_match.group(2),
                                         index_match.group(1))
      unchanged_file_mode = index_match.group(3)
      # Append the unchanged file mode (if it exists) to the index line.
      if unchanged_file_mode:
        inverted_index += ' %s' % unchanged_file_mode
      inverted_header = inverted_header.replace(index_match.group(0),
                                                inverted_index)
    else:
      unchanged_file_mode = None

    # Invert file modes.
    original_new_mode = re.search(r"(?m)^new mode ([0-9]+)", inverted_header)
    original_old_mode = re.search(r"(?m)^old mode ([0-9]+)", inverted_header)
    if original_new_mode and original_old_mode:
      inverted_new_mode = 'new mode %s' % original_old_mode.group(1)
      inverted_old_mode = 'old mode %s' % original_new_mode.group(1)
      inverted_header = inverted_header.replace(original_new_mode.group(0),
                                                inverted_new_mode)
      inverted_header = inverted_header.replace(original_old_mode.group(0),
                                                inverted_old_mode)

    # Do special handling for Binary Files.
    inverted_header = self._get_inverted_header_for_binary_file(
        inverted_header)

    # Do status specific header inversion operations.
    if self._status == COPIED_AND_MODIFIED_STATUS:
       # Need to completely revamp the header for 'A +'.
       new_header = []
       # The first index line does not change.
       new_header.append(inverted_header.split('\n')[0])
       new_header.append('diff --git a/%s b/%s' % (self._filename,
                                                   self._filename))
       # Get the mode of the file to delete.
       if original_new_mode:
         new_header.append('deleted file mode %s' % original_new_mode.group(1))
       elif unchanged_file_mode:
         new_header.append('deleted file mode %s' % unchanged_file_mode)

       if index_match:
         new_header.append('index %s..%s' % (index_match.group(2),
                                             NULL_FILE_HASH))

       # Preserve the 'Binary files..' line if it exists.
       binary_files_match = re.search(r"(?m)^Binary files .*", inverted_header)
       if binary_files_match:
         new_header.append(binary_files_match.group(0))
       
       inverted_header = '\n'.join(new_header) + '\n'
    elif self._status == ADDED_STATUS:
      inverted_header = inverted_header.replace('new file', 'deleted file')
    elif self._status == DELETED_STATUS:
      inverted_header = inverted_header.replace('deleted file', 'new file')

    return inverted_header

  def _get_inverted_header_for_binary_file(self, diff_header):
    # For binary patches we need to reverse the files in the 'Binary files ...'
    # line.
    binary_files_match = re.search(r"(?m)^Binary files (.+?) and (.+?) ",
                                   diff_header)
    if binary_files_match:
      left_binary_file = binary_files_match.group(1)
      right_binary_file = binary_files_match.group(2)
      if (self._status == ADDED_STATUS or
          self._status == COPIED_AND_MODIFIED_STATUS):
        # Below changes
        # 'Binary files /dev/null and b/img/GCE-cloud.png differ' to
        # 'Binary files a/img/GCE-cloud.png and /dev/null differ'
        left_binary_file = 'a/%s' % self._filename
        right_binary_file = NULL_FILE
      elif self._status == DELETED_STATUS:
        # Below changes
        # 'Binary files a/img/GCE-cloud.png and /dev/null differ' to
        # 'Binary files /dev/null and b/img/GCE-cloud.png differ'
        left_binary_file = NULL_FILE
        right_binary_file = 'b/%s' % self._filename
      inverted_differ_text = 'Binary files %s and %s ' % (left_binary_file,
                                                          right_binary_file)
      return diff_header.replace(binary_files_match.group(0),
                                 inverted_differ_text)
    return diff_header
