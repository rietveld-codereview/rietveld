# Copyright (C) 2012 Google Inc.
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

import difflib

class PseudoPatienceSequenceMatcher(difflib.SequenceMatcher):
  """Provides a SequenceMatcher that prefers longer "first" matches to longer
  "second" matches.
  """

  def get_matching_blocks(self):
    """Returns list of triples describing matching subsequences.

    Each triple is of the form (i, j, n), and means that a[i:i+n] == b[j:j+n].
    The triples are monotonically increasing in i and j.

    The last triple is a dummy, and has the value (len(a), len(b), 0). It is the
    only triple with n == 0. If (i, j, n) and (i', j', n') are adjacent triples
    in the list, and the second is not the last triple in the list, then
    i+n != i' or j+n != j'; in other words, adjacent triples always describe
    non-adjacent equal blocks.
    """
    matches = difflib.SequenceMatcher.get_matching_blocks(self)

    # Make sure all elements are of type difflib.Match.
    for index in xrange(len(matches)):
      if not isinstance(matches[index], difflib.Match):
        matches[index] = difflib.Match(matches[index][0],
                                       matches[index][1],
                                       matches[index][2])

    # Check if there's a match at the beginning of the current region, and
    # insert a new Match object at the beginning of |matches| if necessary.
    if matches[0].a != matches[0].b:
      match_length = 0
      index = matches[0].a
      while (index + match_length < len(self.a) and
          index + match_length < len(self.b) and
          self.a[index + match_length] == self.b[index + match_length]):
        match_length += 1

      if match_length:
        matches[0] = difflib.Match(index + match_length,
                                   matches[0].b + match_length,
                                   matches[0].size - match_length)
        if matches[0].size == 0:
          matches[0] = difflib.Match(index, index, match_length)
        else:
          matches.insert(0, difflib.Match(index, index, match_length))

    if len(matches) < 2:
      return matches

    # For all pairs of Match objects, prefer a longer |first| Match if the end
    # of the first match is the same as the beginning of the second match.
    for index in xrange(len(matches) - 2):
      first = matches[index]
      second = matches[index + 1]
      while True:
        if (first.a + first.size < len(self.a) and
            first.b + first.size < len(self.b) and
            second.a < len(self.a) and second.b < len(self.b) and
            self.a[first.a + first.size] == self.b[first.b + first.size] and
            self.a[second.a] == self.b[second.b]):
          first = difflib.Match(first.a, first.b, first.size + 1)
          second = difflib.Match(second.a + 1, second.b + 1, second.size - 1)
        else:
          break
      matches[index] = first
      matches[index + 1] = second

    return matches
