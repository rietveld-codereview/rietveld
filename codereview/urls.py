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
import django.views.defaults
from django.views.generic.simple import redirect_to

from codereview import feeds

urlpatterns = patterns(
    'codereview.views',
    (r'^$', 'index'),

    (r'^leaderboard/?$', redirect_to, {'url': '/leaderboard/30'}),
    (r'^leaderboard_json/(.+)$', 'leaderboard_json'),
    (r'^leaderboard/(.+)$', 'leaderboard'),
    (r'^user/(?P<user>[^/]+)/stats/?$', redirect_to,
        {'url': '/user/%(user)s/stats/30'}),
    (r'^user/([^/]+)/stats/([^/]+)$', 'show_user_stats'),
    (r'^user/([^/]+)/stats_json/([^/]+)$', 'show_user_stats_json'),

    (r'^all$', 'view_all'),
    (r'^mine$', 'mine'),
    (r'^starred$', 'starred'),
    (r'^new$', 'new'),
    (r'^upload$', 'upload'),
    (r'^(\d+)$', 'show', {}, 'show_bare_issue_number'),
    (r'^(\d+)/(show)?$', 'show'),
    (r'^(\d+)/add$', 'add'),
    (r'^(\d+)/edit$', 'edit'),
    (r'^(\d+)/delete$', 'delete'),
    (r'^(\d+)/close$', 'close'),
    (r'^(\d+)/mail$', 'mailissue'),
    (r'^(\d+)/publish$', 'publish'),
    (r'^(\d+)/delete_drafts$', 'delete_drafts'),
    (r'^download/issue(\d+)_(\d+)\.diff', 'download'),
    (r'^download/issue(\d+)_(\d+)_(\d+)\.diff', 'download_patch'),
    (r'^(\d+)/patch/(\d+)/(\d+)$', 'patch'),
    (r'^(\d+)/image/(\d+)/(\d+)/(\d+)$', 'image'),
    (r'^(\d+)/diff/(\d+)/(.+)$', 'diff'),
    (r'^(\d+)/diff2/(\d+):(\d+)/(.+)$', 'diff2'),
    (r'^(\d+)/diff_skipped_lines/(\d+)/(\d+)/(\d+)/(\d+)/([tba])/(\d+)$',
     'diff_skipped_lines'),
    (r'^(\d+)/diff_skipped_lines/(\d+)/(\d+)/$',
     django.views.defaults.page_not_found, {}, 'diff_skipped_lines_prefix'),
    (r'^(\d+)/diff2_skipped_lines/(\d+):(\d+)/(\d+)/(\d+)/(\d+)/([tba])/(\d+)$',
     'diff2_skipped_lines'),
    (r'^(\d+)/diff2_skipped_lines/(\d+):(\d+)/(\d+)/$',
     django.views.defaults.page_not_found, {}, 'diff2_skipped_lines_prefix'),
    (r'^(\d+)/upload_content/(\d+)/(\d+)$', 'upload_content'),
    (r'^(\d+)/upload_patch/(\d+)$', 'upload_patch'),
    (r'^(\d+)/upload_complete/(\d+)?$', 'upload_complete'),
    (r'^(\d+)/description$', 'description'),
    (r'^(\d+)/fields', 'fields'),
    (r'^(\d+)/star$', 'star'),
    (r'^(\d+)/unstar$', 'unstar'),
    (r'^(\d+)/draft_message$', 'draft_message'),
    (r'^api/(\d+)/?$', 'api_issue'),
    (r'^api/(\d+)/(\d+)/?$', 'api_patchset'),
    (r'^api/(\d+)/(\d+)/draft_comments$', 'api_draft_comments'),
    (r'^tarball/(\d+)/(\d+)$', 'tarball'),
    (r'^user/([^/]+)$', 'show_user'),
    (r'^inline_draft$', 'inline_draft'),
    (r'^repos$', 'repos'),
    (r'^repo_new$', 'repo_new'),
    (r'^repo_init$', 'repo_init'),
    (r'^branch_new/(\d+)$', 'branch_new'),
    (r'^branch_edit/(\d+)$', 'branch_edit'),
    (r'^branch_delete/(\d+)$', 'branch_delete'),
    (r'^settings$', 'settings'),
    (r'^account_delete$', 'account_delete'),
    (r'^migrate_entities$', 'migrate_entities'),
    (r'^user_popup/(.+)$', 'user_popup'),
    (r'^(\d+)/patchset/(\d+)$', 'patchset'),
    (r'^(\d+)/patchset/(\d+)/delete$', 'delete_patchset'),

    (r'^restricted/cron/update_yesterday_stats$',
        'cron_update_yesterday_stats'),
    (r'^restricted/tasks/refresh_all_stats_score$',
        'task_refresh_all_stats_score'),
    (r'^restricted/tasks/update_stats$', 'task_update_stats'),
    (r'^restricted/update_stats$', 'update_stats'),

    (r'^account$', 'account'),
    (r'^use_uploadpy$', 'use_uploadpy'),
    (r'^xsrf_token$', 'xsrf_token'),
    # patching upload.py on the fly
    (r'^static/upload.py$', 'customized_upload_py'),
    (r'^search$', 'search'),
    (r'^get-access-token$', 'get_access_token'),
    (r'^oauth2callback$', 'oauth2callback'),
    # Restricted access.
    (r'^restricted/set-client-id-and-secret$', 'set_client_id_and_secret'),
    (r'^restricted/tasks/calculate_delta$', 'task_calculate_delta'),
    (r'^restricted/tasks/migrate_entities$', 'task_migrate_entities'),
    (r'^restricted/user/([^/]+)/block$', 'block_user'),
    (r'^_ah/xmpp/message/chat/', 'incoming_chat'),
    (r'^_ah/mail/(.*)', 'incoming_mail'),
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
