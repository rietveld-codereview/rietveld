# Starting a Code Review #

A _patch set_ is a set of diffs relative to a specific revision of
the files in a particular VCS repository.  The format used
is a _unified diff_ as output by the `diff` command of the underlying
version control system.

There are three ways to start a code review:

1. Recommended way is to use a small command line utility
[upload.py](http://codereview.appspot.com/static/upload.py) (requires Python 2.5+ - no Python 3 yet). In `*`nix you may want to install it in your personal bin directory with mode 755.  This is by far the most convenient and versatile approach, because the utility is able to extract all required information automatically, and all you have to do is enter a brief message to be used as the subject line.  The utility prints the
URL for your newly created issue.

2. Upload a patch set to the web app using the
[Create Issue](http://codereview.appspot.com/new) form. Not recommended, because most contributors use `upload.py`, and its interface is supported better.

3. Let the web part of Rietveld fetch the patch set from another web server, for
example the [Python issue tracker](http://bugs.python.org).
This is also done via the
[Create Issue](http://codereview.appspot.com//new) form, using
the "Url" field.


### Adding patch sets ###

It is possible to add a new patch set to an existing issue.
When you used the "Create Issue" form initially, you can use the
"Add Another Patch Set" section that appears below the last patch set added.
When you used the upload.py utility, you can pass the "-i NNNN" flag to the
utility, where NNNN is the numeric Issue ID.

Once you have two or more patch sets in an issue, you can view the delta
between any two patch sets by using the "Delta from patch set" links
in the last column of the file list for any patch set.

All but the most recent patch set listings are normally collapsed;
you must click on the patch set heading to reveal the list of files
in older patch sets.

# Inviting a Reviewer #

To invite a reviewer for a particular issue, go to the page with
details about the issue, and follow the "Publish+Mail Comments" link.
This brings you to a simple form where you can add the reviewer's
email address or nickname to the "Reviewers" field and enter a brief message
explaining to them the purpose of the review.  Clicking on "Publish
All My Drafts" (the odd label will become clear later) will then send
them an email.  You can invite multiple reviewers by entering their
email addresses or nicknames separated by commas.
Only the "user@domain.suffix" part of the email must be entered: do not
enter the real name.

Anybody can change the list of reviewers this way.  The issue owner
can also edit the list of reviewers using the "Edit Issue" form.

When you use the upload.py utility, you can pass the "-r REVIEWER" flag to
the utility, where REVIEWER is the reviewers email address or nickname.

# Conducting a Review #

If you're invited to a review, you'll follow the link in the email,
which takes you to the issue detail page.  On that page you'll see a
list of files.  Selecting the filename will take you to a copy of the
unified diff, which is not too interesting.
However, following the link labeled "View"
takes you to a double source listing, a so-called
_side-by-side diff_ where the old version of the file is on the left
and the new version is on the right.  Deletions on the left are shown
with a red background, additions on the right with a green background.

### Navigating the Diff ###

In order to jump straight to the first diff chunk, hit the 'n' key
once or twice.  Each time you hit 'n' you are taken to the next chunk,
until you have reached the end of the file.  You can also use 'p' to
move back up.  Later, once there are in-line comments, these commands
also stop at comments; use 'N' and 'P' to jump between comments only.

Long stretches of matching lines are suppressed; you'll see the text
_(...skipping N matching lines...)_ on a light blue background.
this is done to avoid exceeding the strict limits enforced by App Engine
on response size (1 MB) and request processing time (10 seconds).

If the patch set consists of multiple files, you can navigate
between files using 'j' (next file) and 'k' (previous file).
(_Vi_, _Vim_ or _Gmail_ users can think of these commands moving up
('k) or down ('j') in the list of files that you saw earlier.)

### Entering In-line Comments ###

When you see something in the code you want to comment on, simply
**double-click** the line on which you want to comment.  Through
the magic of JavaScript, a small text editing dialog will open up
below that line, where you can enter as much text as you want.
(There's a small '+' icon to the right that makes the text area larger
each time you click it.)  When you're done with a comment, don't
forget to click the "Save" button (hitting Control-s works too).  If
you clicked "Save" too soon or change your mind, you can always hit
the "Edit" link that appears under the completed comment, and edit or
discard it.

### Publishing In-line Comments ###

**You're not done yet!** Once you have splattered comments all
over the files in the patch set, there's one more thing to do: you
must _publish_ your comments!  So far, all your comments have
been stored in the database as drafts, which means that only you can
see and edit them.  To remind you of this "limbo" state, the issue
page lists the number of draft comments in red, and displays a pretty
alarming warning at the top when you have any draft comments.  To get
rid of this, follow one of the "Publish+Main Comments" links (there
are several on the diff page as well as on the issue page), enter a
brief message, and click "Publish All My Drafts".  This will send an
email to the issue owner and to all reviewers, and publish your drafts
on the web app so that others can see them.  (If you'd rather not send
email, you can uncheck the "Send mail" check box.)

### Closing the Issue ###

An issue's owner can close the issue by using the "Edit Issue" form and
checking the "Closed" box.  Closed issues are hidden from most overview
listings but can otherwise continue to be used.  An issue's owner can
reopen the issue by unchecking the "Closed" box.

An issue's owner can also delete the issue.  This is irrevocable and
all traces of the issue are removed from the data store.
There is no undo and no backup.  Regrets are not accepted.

There are few good reasons to delete an issue: cleaning up test issues
is one, removing sensitive information accidentally posted is another.

# Access Control #

Apart from **draft** comments, which are only visible to their
author, all comments are visible to anyone who visits the site, even
if they are not logged in.  Anybody can view all issues, too.  Only
the owner of an issue can edit its subject, description, and list of
reviewers, but anybody (even people not listed as reviewers) can add
new comments to an issue.  Comments however cannot be entered
anonymously; you must be logged in.

# Using Code Reviews with Google Apps #

### How do I set up Google Code Reviews for my organization? ###

Google Code Reviews is available to Google Apps customers as part of Labs for Google Apps.

If you are an existing Google Apps customer, proceed to the [Google Solutions Marketplace](http://www.google.com/enterprise/marketplace/viewVendorListings?vendorId=1012), click 'Add It Now' and follow the instructions. When installing Google Code Reviews for your domain, you will be prompted to assign a custom URL for the service like 'cr.example.com'.

If you are not currently using Google Apps [go sign up](http://google.com/a) before visiting the Solutions Marketplace.

### Why should I use Google Code Reviews on my domain? ###

Using Google Code Reviews on your domain allows you to do the following:
host on a custom url for your domain, e.g. cr.example.com
make code changes and comments entirely internal to your organization
optionally allow outside parties to view your content, but not participate

### How do I administer Google Code Reviews for my domain? ###

Once installed, you can go to http://google.com/a/example.com/LabServiceSettings?appId=codereview to manage or remove the application.

### I have private feedback for Google Code Reviews for Google Apps ###

Please send your feedback to code-reviews-for-apps-feedback@groups.google.com