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

"""URL mappings for the codereview package."""

# NOTE: Must import *, since Django looks for things here, e.g. handler500.
from django.conf.urls.defaults import *

from codereview import feeds

urlpatterns = patterns(
    'codereview.views',
    (r'^$', 'index'),
    (r'^all$', 'all'),
    (r'^mine$', 'mine'),
    (r'^overview', 'overview'),
    (r'^starred$', 'starred'),
    (r'^new$', 'new'),
    (r'^upload$', 'upload'),
    (r'^(\d+)$', 'show'),
    (r'^(\d+)/show$', 'show'),
    (r'^(\d+)/add$', 'add'),
    (r'^(\d+)/edit$', 'edit'),
    (r'^(\d+)/delete$', 'delete'),
    (r'^(\d+)/close$', 'close'),
    (r'^(\d+)/mail$', 'mailissue'),
    (r'^(\d+)/publish$', 'publish'),
    (r'^download/issue(\d+)_(\d+)\.diff', 'download'),
    (r'^download/issue(\d+)_(\d+)_(\d+)\.diff', 'download_patch'),
    (r'^(\d+)/patch/(\d+)/(\d+)$', 'patch'),
    (r'^(\d+)/image/(\d+)/(\d+)/(\d+)$', 'image'),
    (r'^(\d+)/diff/(\d+)/(\d+)$', 'diff'),
    (r'^(\d+)/diff2/(\d+):(\d+)/(\d+)$', 'diff2'),
    (r'^(\d+)/diff_skipped_lines/(\d+)/(\d+)/(\d+)/(\d+)/([tba])/(\d+)$',
     'diff_skipped_lines'),
    (r'^(\d+)/diff2_skipped_lines/(\d+):(\d+)/(\d+)/(\d+)/(\d+)/([tba])/(\d+)$',
     'diff2_skipped_lines'),
    (r'^(\d+)/upload_content/(\d+)/(\d+)$', 'upload_content'),
    (r'^(\d+)/upload_patch/(\d+)$', 'upload_patch'),
    (r'^(\d+)/upload_build_result/(\d+)$', 'upload_build_result'),
    (r'^(\d+)/get_build_results/(\d+)$', 'get_build_results'),
    (r'^(\d+)/description$', 'description'),
    (r'^(\d+)/star$', 'star'),
    (r'^(\d+)/unstar$', 'unstar'),
    (r'^(\d+)/draft_message$', 'draft_message'),
    (r'^user/(.+)$', 'show_user'),
    (r'^inline_draft$', 'inline_draft'),
    (r'^repos$', 'repos'),
    (r'^repo_new$', 'repo_new'),
    (r'^repo_init$', 'repo_init'),
    (r'^branch_new/(\d+)$', 'branch_new'),
    (r'^branch_edit/(\d+)$', 'branch_edit'),
    (r'^branch_delete/(\d+)$', 'branch_delete'),
    (r'^settings$', 'settings'),
    (r'^account_delete$', 'account_delete'),
    (r'^user_popup/(.+)$', 'user_popup'),
    (r'^(\d+)/patchset/(\d+)$', 'patchset'),
    (r'^(\d+)/patchset/(\d+)/delete$', 'delete_patchset'),
    (r'^account$', 'account'),
    (r'^use_uploadpy$', 'use_uploadpy'),
    (r'^_ah/xmpp/message/chat/', 'incoming_chat'),
    (r'^_ah/mail/(.*)', 'incoming_mail'),
    (r'^lint/issue(\d+)_(\d+)', 'lint'),
    (r'^lint_patch/issue(\d+)_(\d+)_(\d+)', 'lint_patch'),
    )

feed_dict = {
  'reviews': feeds.ReviewsFeed,
  'closed': feeds.ClosedFeed,
  'mine' : feeds.MineFeed,
  'all': feeds.AllFeed,
  'issue' : feeds.OneIssueFeed,
}

urlpatterns += patterns(
    '',
    (r'^rss/(?P<url>.*)$', 'django.contrib.syndication.views.feed',
     {'feed_dict': feed_dict}),
    )
