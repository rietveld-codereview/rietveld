#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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

"""Tool for uploading diffs from a version control system to the codereview app.

Usage summary: upload.py [options] [-- diff_options]

Diff options are passed to the diff command of the underlying system.

Supported version control systems:
  Git
  Subversion

(It is important for Git users to specify a tree-ish to diff against.)
"""
# This code is derived from appcfg.py in the App Engine SDK (open source),
# and from ASPN recipe #146306.

import cookielib
import getpass
import logging
import md5
import mimetypes
import optparse
import os
import re
import socket
import subprocess
import sys
import urllib
import urllib2
import urlparse

try:
  import readline
except ImportError:
  pass

# The logging verbosity:
#  0: Errors only.
#  1: Status messages.
#  2: Info logs.
#  3: Debug logs.
verbosity = 1

# Max size of patch or base file.
MAX_UPLOAD_SIZE = 900 * 1024


def StatusUpdate(msg):
  """Print a status message to stdout.

  If 'verbosity' is greater than 0, print the message.

  Args:
    msg: The string to print.
  """
  if verbosity > 0:
    print msg


def ErrorExit(msg):
  """Print an error message to stderr and exit."""
  print >>sys.stderr, msg
  sys.exit(1)


class ClientLoginError(urllib2.HTTPError):
  """Raised to indicate there was an error authenticating with ClientLogin."""

  def __init__(self, url, code, msg, headers, args):
    urllib2.HTTPError.__init__(self, url, code, msg, headers, None)
    self.args = args
    self.reason = args["Error"]


class AbstractRpcServer(object):
  """Provides a common interface for a simple RPC server."""

  def __init__(self, host, auth_function, host_override=None, extra_headers={},
               save_cookies=False):
    """Creates a new HttpRpcServer.

    Args:
      host: The host to send requests to.
      auth_function: A function that takes no arguments and returns an
        (email, password) tuple when called. Will be called if authentication
        is required.
      host_override: The host header to send to the server (defaults to host).
      extra_headers: A dict of extra headers to append to every request.
      save_cookies: If True, save the authentication cookies to local disk.
        If False, use an in-memory cookiejar instead.  Subclasses must
        implement this functionality.  Defaults to False.
    """
    self.host = host
    self.host_override = host_override
    self.auth_function = auth_function
    self.authenticated = False
    self.extra_headers = extra_headers
    self.save_cookies = save_cookies
    self.opener = self._GetOpener()
    if self.host_override:
      logging.info("Server: %s; Host: %s", self.host, self.host_override)
    else:
      logging.info("Server: %s", self.host)

  def _GetOpener(self):
    """Returns an OpenerDirector for making HTTP requests.

    Returns:
      A urllib2.OpenerDirector object.
    """
    raise NotImplementedError()

  def _CreateRequest(self, url, data=None):
    """Creates a new urllib request."""
    logging.debug("Creating request for: '%s' with payload:\n%s", url, data)
    req = urllib2.Request(url, data=data)
    if self.host_override:
      req.add_header("Host", self.host_override)
    for key, value in self.extra_headers.iteritems():
      req.add_header(key, value)
    return req

  def _GetAuthToken(self, email, password):
    """Uses ClientLogin to authenticate the user, returning an auth token.

    Args:
      email:    The user's email address
      password: The user's password

    Raises:
      ClientLoginError: If there was an error authenticating with ClientLogin.
      HTTPError: If there was some other form of HTTP error.

    Returns:
      The authentication token returned by ClientLogin.
    """
    req = self._CreateRequest(
        url="https://www.google.com/accounts/ClientLogin",
        data=urllib.urlencode({
            "Email": email,
            "Passwd": password,
            "service": "ah",
            "source": "rietveld-codereview-upload",
            "accountType": "GOOGLE",
        })
    )
    try:
      response = self.opener.open(req)
      response_body = response.read()
      response_dict = dict(x.split("=")
                           for x in response_body.split("\n") if x)
      return response_dict["Auth"]
    except urllib2.HTTPError, e:
      if e.code == 403:
        body = e.read()
        response_dict = dict(x.split("=", 1) for x in body.split("\n") if x)
        raise ClientLoginError(req.get_full_url(), e.code, e.msg,
                               e.headers, response_dict)
      else:
        raise

  def _GetAuthCookie(self, auth_token):
    """Fetches authentication cookies for an authentication token.

    Args:
      auth_token: The authentication token returned by ClientLogin.

    Raises:
      HTTPError: If there was an error fetching the authentication cookies.
    """
    # This is a dummy value to allow us to identify when we're successful.
    continue_location = "http://localhost/"
    args = {"continue": continue_location, "auth": auth_token}
    req = self._CreateRequest("http://%s/_ah/login?%s" %
                              (self.host, urllib.urlencode(args)))
    try:
      response = self.opener.open(req)
    except urllib2.HTTPError, e:
      response = e
    if (response.code != 302 or
        response.info()["location"] != continue_location):
      raise urllib2.HTTPError(req.get_full_url(), response.code, response.msg,
                              response.headers, response.fp)
    self.authenticated = True

  def _Authenticate(self):
    """Authenticates the user.

    The authentication process works as follows:
     1) We get a username and password from the user
     2) We use ClientLogin to obtain an AUTH token for the user
        (see http://code.google.com/apis/accounts/AuthForInstalledApps.html).
     3) We pass the auth token to /_ah/login on the server to obtain an
        authentication cookie. If login was successful, it tries to redirect
        us to the URL we provided.

    If we attempt to access the upload API without first obtaining an
    authentication cookie, it returns a 401 response and directs us to
    authenticate ourselves with ClientLogin.
    """
    for i in range(3):
      credentials = self.auth_function()
      try:
        auth_token = self._GetAuthToken(credentials[0], credentials[1])
      except ClientLoginError, e:
        if e.reason == "BadAuthentication":
          print >>sys.stderr, "Invalid username or password."
          continue
        if e.reason == "CaptchaRequired":
          print >>sys.stderr, (
              "Please go to\n"
              "https://www.google.com/accounts/DisplayUnlockCaptcha\n"
              "and verify you are a human.  Then try again.")
          break
        if e.reason == "NotVerified":
          print >>sys.stderr, "Account not verified."
          break
        if e.reason == "TermsNotAgreed":
          print >>sys.stderr, "User has not agreed to TOS."
          break
        if e.reason == "AccountDeleted":
          print >>sys.stderr, "The user account has been deleted."
          break
        if e.reason == "AccountDisabled":
          print >>sys.stderr, "The user account has been disabled."
          break
        if e.reason == "ServiceDisabled":
          print >>sys.stderr, ("The user's access to the service has been "
                               "disabled.")
          break
        if e.reason == "ServiceUnavailable":
          print >>sys.stderr, "The service is not available; try again later."
          break
        raise
      self._GetAuthCookie(auth_token)
      return

  def Send(self, request_path, payload=None,
           content_type="application/octet-stream",
           timeout=None,
           **kwargs):
    """Sends an RPC and returns the response.

    Args:
      request_path: The path to send the request to, eg /api/appversion/create.
      payload: The body of the request, or None to send an empty request.
      content_type: The Content-Type header to use.
      timeout: timeout in seconds; default None i.e. no timeout.
        (Note: for large requests on OS X, the timeout doesn't work right.)
      kwargs: Any keyword arguments are converted into query string parameters.

    Returns:
      The response body, as a string.
    """
    # TODO: Don't require authentication.  Let the server say
    # whether it is necessary.
    if not self.authenticated:
      self._Authenticate()

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
      tries = 0
      while True:
        tries += 1
        args = dict(kwargs)
        url = "http://%s%s" % (self.host, request_path)
        if args:
          url += "?" + urllib.urlencode(args)
        req = self._CreateRequest(url=url, data=payload)
        req.add_header("Content-Type", content_type)
        try:
          f = self.opener.open(req)
          response = f.read()
          f.close()
          return response
        except urllib2.HTTPError, e:
          if tries > 3:
            raise
          elif e.code == 401:
            self._Authenticate()
##           elif e.code >= 500 and e.code < 600:
##             # Server Error - try again.
##             continue
          else:
            raise
    finally:
      socket.setdefaulttimeout(old_timeout)


class HttpRpcServer(AbstractRpcServer):
  """Provides a simplified RPC-style interface for HTTP requests."""

  def _Authenticate(self):
    """Save the cookie jar after authentication."""
    super(HttpRpcServer, self)._Authenticate()
    if self.save_cookies:
      StatusUpdate("Saving authentication cookies to %s" % self.cookie_file)
      self.cookie_jar.save()

  def _GetOpener(self):
    """Returns an OpenerDirector that supports cookies and ignores redirects.

    Returns:
      A urllib2.OpenerDirector object.
    """
    opener = urllib2.OpenerDirector()
    opener.add_handler(urllib2.ProxyHandler())
    opener.add_handler(urllib2.UnknownHandler())
    opener.add_handler(urllib2.HTTPHandler())
    opener.add_handler(urllib2.HTTPDefaultErrorHandler())
    opener.add_handler(urllib2.HTTPSHandler())
    opener.add_handler(urllib2.HTTPErrorProcessor())
    if self.save_cookies:
      self.cookie_file = os.path.expanduser("~/.codereview_upload_cookies")
      self.cookie_jar = cookielib.MozillaCookieJar(self.cookie_file)
      if os.path.exists(self.cookie_file):
        try:
          self.cookie_jar.load()
          self.authenticated = True
          StatusUpdate("Loaded authentication cookies from %s" %
                       self.cookie_file)
        except (cookielib.LoadError, IOError):
          # Failed to load cookies - just ignore them.
          pass
      else:
        # Create an empty cookie file with mode 600
        fd = os.open(self.cookie_file, os.O_CREAT, 0600)
        os.close(fd)
      # Always chmod the cookie file
      os.chmod(self.cookie_file, 0600)
    else:
      # Don't save cookies across runs of update.py.
      self.cookie_jar = cookielib.CookieJar()
    opener.add_handler(urllib2.HTTPCookieProcessor(self.cookie_jar))
    return opener


parser = optparse.OptionParser(usage="%prog [options] [-- diff_options]")
parser.add_option("-y", "--assume_yes", action="store_true",
                  dest="assume_yes", default=False,
                  help="Assume that the answer to yes/no questions is 'yes'.")
# Logging
group = parser.add_option_group("Logging options")
group.add_option("-q", "--quiet", action="store_const", const=0,
                 dest="verbose", help="Print errors only.")
group.add_option("-v", "--verbose", action="store_const", const=2,
                 dest="verbose", default=1,
                 help="Print info level logs (default).")
group.add_option("--noisy", action="store_const", const=3,
                 dest="verbose", help="Print all logs.")
# Review server
group = parser.add_option_group("Review server options")
group.add_option("-s", "--server", action="store", dest="server",
                 default="codereview.appspot.com",
                 metavar="SERVER",
                 help=("The server to upload to. The format is host[:port]. "
                       "Defaults to 'codereview.appspot.com'."))
group.add_option("-e", "--email", action="store", dest="email",
                 metavar="EMAIL", default=None,
                 help="The username to use. Will prompt if omitted.")
group.add_option("-H", "--host", action="store", dest="host",
                 metavar="HOST", default=None,
                 help="Overrides the Host header sent with all RPCs.")
group.add_option("--no_cookies", action="store_false",
                 dest="save_cookies", default=True,
                 help="Do not save authentication cookies to local disk.")
# Issue
group = parser.add_option_group("Issue options")
group.add_option("-d", "--description", action="store", dest="description",
                 metavar="DESCRIPTION", default=None,
                 help="Optional description when creating an issue.")
group.add_option("-f", "--description_file", action="store",
                 dest="description_file", metavar="DESCRIPTION_FILE",
                 default=None,
                 help="Optional path of a file that contains "
                      "the description when creating an issue.")
group.add_option("-r", "--reviewers", action="store", dest="reviewers",
                 metavar="REVIEWERS", default=None,
                 help="Add reviewers (comma separated email addresses).")
group.add_option("--cc", action="store", dest="cc",
                 metavar="CC", default=None,
                 help="Add CC (comma separated email addresses).")
# Upload options
group = parser.add_option_group("Patch options")
group.add_option("-m", "--message", action="store", dest="message",
                 metavar="MESSAGE", default=None,
                 help="A message to identify the patch. "
                      "Will prompt if omitted.")
group.add_option("-i", "--issue", type="int", action="store",
                 metavar="ISSUE", default=None,
                 help="Issue number to which to add. Defaults to new issue.")
group.add_option("-l", "--local_base", action="store_true",
                 dest="local_base", default=False,
                 help="Base files will be uploaded.")
group.add_option("--send_mail", action="store_true",
                 dest="send_mail", default=False,
                 help="Send notification email to reviewers.")


def GetRpcServer(options):
  """Returns an instance of an AbstractRpcServer.

  Returns:
    A new AbstractRpcServer, on which RPC calls can be made.
  """

  rpc_server_class = HttpRpcServer

  def GetUserCredentials():
    """Prompts the user for a username and password."""
    email = options.email
    if email is None:
      email = raw_input("Email: ").strip()
    password = getpass.getpass("Password for %s: " % email)
    return (email, password)

  # If this is the dev_appserver, use fake authentication.
  host = (options.host or options.server).lower()
  if host == "localhost" or host.startswith("localhost:"):
    email = options.email
    if email is None:
      email = "test@example.com"
      logging.info("Using debug user %s.  Override with --email" % email)
    server = rpc_server_class(
        options.server,
        lambda: (email, "password"),
        host_override=options.host,
        extra_headers={"Cookie":
                       'dev_appserver_login="%s:False"' % email},
        save_cookies=options.save_cookies)
    # Don't try to talk to ClientLogin.
    server.authenticated = True
    return server

  return rpc_server_class(options.server, GetUserCredentials,
                          host_override=options.host,
                          save_cookies=options.save_cookies)


def EncodeMultipartFormData(fields, files):
  """Encode form fields for multipart/form-data.

  Args:
    fields: A sequence of (name, value) elements for regular form fields.
    files: A sequence of (name, filename, value) elements for data to be
           uploaded as files.
  Returns:
    (content_type, body) ready for httplib.HTTP instance.

  Source:
    http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/146306
  """
  BOUNDARY = '-M-A-G-I-C---B-O-U-N-D-A-R-Y-'
  CRLF = '\r\n'
  lines = []
  for (key, value) in fields:
    lines.append('--' + BOUNDARY)
    lines.append('Content-Disposition: form-data; name="%s"' % key)
    lines.append('')
    lines.append(value)
  for (key, filename, value) in files:
    lines.append('--' + BOUNDARY)
    lines.append('Content-Disposition: form-data; name="%s"; filename="%s"' %
             (key, filename))
    lines.append('Content-Type: %s' % GetContentType(filename))
    lines.append('')
    lines.append(value)
  lines.append('--' + BOUNDARY + '--')
  lines.append('')
  body = CRLF.join(lines)
  content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
  return content_type, body


def GetContentType(filename):
  """Helper to guess the content-type from the filename."""
  return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


# Use a shell for subcommands on Windows to get a PATH search.
use_shell = sys.platform.startswith("win")


def RunShell(command, silent_ok=False, universal_newlines=False):
  logging.info("Running %s", command)
  p = subprocess.Popen(command, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, shell=use_shell,
                       universal_newlines=universal_newlines)
  data = p.stdout.read()
  p.wait()
  p.stdout.close()
  if p.returncode:
    ErrorExit("Got error status from %s" % command)
  if not silent_ok and not data:
    ErrorExit("No output from %s" % command)
  return data


class VersionControlSystem(object):
  """Abstract base class providing an interface to the VCS."""

  def GenerateDiff(self, args):
    """Return the current diff as a string.

    Args:
      args: Extra arguments to pass to the diff command.
    """
    raise NotImplementedError(
        "abstract method -- subclass %s must override" % self.__class__)

  def GetUnknownFiles(self):
    """Return a list of files unknown to the VCS."""
    raise NotImplementedError(
        "abstract method -- subclass %s must override" % self.__class__)

  def CheckForUnknownFiles(self):
    """Show an "are you sure?" prompt if there are unknown files."""
    unknown_files = self.GetUnknownFiles()
    if unknown_files:
      print "The following files are not added to version control:"
      for line in unknown_files:
        print line
      prompt = "Are you sure to continue?(y/N) "
      answer = raw_input(prompt).strip()
      if answer != "y":
        ErrorExit("User aborted")

  def GetBaseFile(self, filename):
    """Get the content of the upstream version of a file.

    Returns:
      A tuple (content, status) representing the file content and the status of
      the file.
    """

    raise NotImplementedError(
        "abstract method -- subclass %s must override" % self.__class__)

  def UploadBaseFiles(self, issue, rpc_server, patch_list, patchset, options):
    """Uploads the base files."""
    patches = dict()
    [patches.setdefault(v, k) for k, v in patch_list]
    for filename in patches.keys():
      content, status = self.GetBaseFile(filename)
      no_base_file = False
      if len(content) > MAX_UPLOAD_SIZE:
        print ("Not uploading the base file for " + filename +
               " because the file is too large.")
        no_base_file = True
        content = ""
      checksum = md5.new(content).hexdigest()
      if options.verbose > 0:
        print "Uploading %s" % filename
      url = "/%d/upload_content/%d/%d" % (int(issue), int(patchset),
                                          int(patches.get(filename)))
      form_fields = [("filename", filename),
                     ("status", status),
                     ("checksum", checksum),]
      if no_base_file:
        form_fields.append(("no_base_file", "1"))
      if options.email:
        form_fields.append(("user", options.email))
      ctype, body = EncodeMultipartFormData(form_fields,
                                            [("data", filename, content)])
      response_body = rpc_server.Send(url, body, content_type=ctype)
      if not response_body.startswith("OK"):
        StatusUpdate("  --> %s" % response_body)
        sys.exit(False)


class SubversionVCS(VersionControlSystem):
  """Implementation of the VersionControlSystem interface for Subversion."""

  def GuessBase(self, required):
    """Returns the SVN base URL.

    Args:
      required: If true, exits if the url can't be guessed, otherwise None is
        returned.
    """
    info = RunShell(["svn", "info"])
    for line in info.splitlines():
      words = line.split()
      if len(words) == 2 and words[0] == "URL:":
        url = words[1]
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
        username, netloc = urllib.splituser(netloc)
        if username:
          logging.info("Removed username from base URL")
        if netloc.endswith("svn.python.org"):
          if netloc == "svn.python.org":
            if path.startswith("/projects/"):
              path = path[9:]
          elif netloc != "pythondev@svn.python.org":
            ErrorExit("Unrecognized Python URL: %s" % url)
          base = "http://svn.python.org/view/*checkout*%s/" % path
          logging.info("Guessed Python base = %s", base)
        elif netloc.endswith("svn.collab.net"):
          if path.startswith("/repos/"):
            path = path[6:]
          base = "http://svn.collab.net/viewvc/*checkout*%s/" % path
          logging.info("Guessed CollabNet base = %s", base)
        elif netloc.endswith(".googlecode.com"):
          path = path + "/"
          base = urlparse.urlunparse(("http", netloc, path, params,
                                      query, fragment))
          logging.info("Guessed Google Code base = %s", base)
        else:
          path = path + "/"
          base = urlparse.urlunparse((scheme, netloc, path, params,
                                      query, fragment))
          logging.info("Guessed base = %s", base)
        return base
    if required:
      ErrorExit("Can't find URL in output from svn info")
    return None

  def GenerateDiff(self, args):
    cmd = ["svn", "diff"]
    if not sys.platform.startswith("win"):
      cmd.append("--diff-cmd=diff")
    cmd.extend(args)
    data = RunShell(cmd)
    count = 0
    for line in data.splitlines():
      if line.startswith("Index:") or line.startswith("Property changes on:"):
        count += 1
        logging.info(line)
    if not count:
      ErrorExit("No valid patches found in output from svn diff")
    return data

  def _CollapseKeywords(self, content, keyword_str):
    """Collapses SVN keywords."""
    # svn cat translates keywords but svn diff doesn't. As a result of this
    # behavior patching.PatchChunks() fails with a chunk mismatch error.
    # This part was originally written by the Review Board development team
    # who had the same problem (http://reviews.review-board.org/r/276/).
    # Mapping of keywords to known aliases
    svn_keywords = {
      # Standard keywords
      'Date':                ['Date', 'LastChangedDate'],
      'Revision':            ['Revision', 'LastChangedRevision', 'Rev'],
      'Author':              ['Author', 'LastChangedBy'],
      'HeadURL':             ['HeadURL', 'URL'],
      'Id':                  ['Id'],

      # Aliases
      'LastChangedDate':     ['LastChangedDate', 'Date'],
      'LastChangedRevision': ['LastChangedRevision', 'Rev', 'Revision'],
      'LastChangedBy':       ['LastChangedBy', 'Author'],
      'URL':                 ['URL', 'HeadURL'],
    }
    def repl(m):
       if m.group(2):
         return "$%s::%s$" % (m.group(1), " " * len(m.group(3)))
       return "$%s$" % m.group(1)
    keywords = [keyword
                for name in keyword_str.split(" ")
                for keyword in svn_keywords.get(name, [])]
    return re.sub(r"\$(%s):(:?)([^\$]+)\$" % '|'.join(keywords), repl, content)

  def GetUnknownFiles(self):
    status = RunShell(["svn", "status", "--ignore-externals"], silent_ok=True)
    unknown_files = []
    for line in status.split("\n"):
      if line and line[0] == "?":
        unknown_files.append(line)
    return unknown_files

  def GetBaseFile(self, filename):
    status = RunShell(["svn", "status", "--ignore-externals", filename])
    if not status:
      StatusUpdate("svn status returned no output for %s" % filename)
      sys.exit(False)
    status_lines = status.splitlines()
    # If file is in a cl, the output will begin with
    # "\n--- Changelist 'cl_name':\n".  See
    # http://svn.collab.net/repos/svn/trunk/notes/changelist-design.txt
    if (len(status_lines) == 3 and
        not status_lines[0] and
        status_lines[1].startswith("--- Changelist")):
      status = status_lines[2]
    else:
      status = status_lines[0]
    # If a file is copied its status will be "A  +", which signifies
    # "addition-with-history".  See "svn st" for more information.  We need to
    # upload the original file or else diff parsing will fail if the file was
    # edited.
    if ((status[0] == "A" and status[3] != "+") or
        (status[0] == " " and status[1] == "M")):  # property changed
      content = ""
    elif (status[0] in ("M", "D", "R") or
          (status[0] == "A" and status[3] == "+")):
      mimetype = RunShell(["svn", "-rBASE", "propget", "svn:mime-type",
                           filename],
                          silent_ok=True)
      if mimetype.startswith("application/octet-stream"):
        content = ""
      else:
        # On Windows svn cat gives \r\n, and calling subprocess.Popen turns
        # them into \r\r\n, so use universal newlines to avoid the extra \r.
        if sys.platform.startswith("win"):
          nl = True
        else:
          nl = False
        content = RunShell(["svn", "cat", filename], universal_newlines=nl)
      keywords = RunShell(["svn", "-rBASE", "propget", "svn:keywords",
                           filename],
                          silent_ok=True)
      if keywords:
        content = self._CollapseKeywords(content, keywords)
    else:
      StatusUpdate("svn status returned unexpected output: %s" % status)
      sys.exit(False)
    return content, status[0:5]


class GitVCS(VersionControlSystem):
  """Implementation of the VersionControlSystem interface for Git."""

  def __init__(self):
    # Map of filename -> hash of base file.
    self.base_hashes = {}

  def GenerateDiff(self, extra_args):
    # This is more complicated than svn's GenerateDiff because we must convert
    # the diff output to include an svn-style "Index:" line as well as record
    # the hashes of the base files, so we can upload them along with our diff.
    gitdiff = RunShell(["git", "diff", "--full-index"] + extra_args)
    svndiff = []
    filecount = 0
    filename = None
    for line in gitdiff.splitlines():
      match = re.match(r"diff --git a/(.*) b/.*$", line)
      if match:
        filecount += 1
        filename = match.group(1)
        svndiff.append("Index: %s\n" % filename)
      else:
        # The "index" line in a git diff looks like this (long hashes elided):
        #   index 82c0d44..b2cee3f 100755
        # We want to save the left hash, as that identifies the base file.
        match = re.match(r"index (\w+)\.\.", line)
        if match:
          self.base_hashes[filename] = match.group(1)
      svndiff.append(line + "\n")
    if not filecount:
      ErrorExit("No valid patches found in output from git diff")
    return "".join(svndiff)

  def GetUnknownFiles(self):
    status = RunShell(["git", "ls-files", "--others"], silent_ok=True)
    return status.splitlines()

  def GetBaseFile(self, filename):
    hash = self.base_hashes[filename]
    if hash == "0" * 40:  # All-zero hash indicates no base file.
      return ("", "A")
    else:
      return (RunShell(["git", "show", hash]), "M")


# NOTE: this function is duplicated in engine.py, keep them in sync.
def SplitPatch(data):
  """Splits a patch into separate pieces for each file.

  Args:
    data: A string containing the output of svn diff.

  Returns:
    A list of 2-tuple (filename, text) where text is the svn diff output
      pertaining to filename.
  """
  patches = []
  filename = None
  diff = []
  for line in data.splitlines(True):
    new_filename = None
    if line.startswith('Index:'):
      unused, new_filename = line.split(':', 1)
      new_filename = new_filename.strip()
    elif line.startswith('Property changes on:'):
      unused, temp_filename = line.split(':', 1)
      # When a file is modified, paths use '/' between directories, however
      # when a property is modified '\' is used on Windows.  Make them the same
      # otherwise the file shows up twice.
      temp_filename = temp_filename.strip().replace('\\', '/')
      if temp_filename != filename:
        # File has property changes but no modifications, create a new diff.
        new_filename = temp_filename
    if new_filename:
      if filename and diff:
        patches.append((filename, ''.join(diff)))
      filename = new_filename
      diff = [line]
      continue
    if diff is not None:
      diff.append(line)
  if filename and diff:
    patches.append((filename, ''.join(diff)))
  return patches


def UploadSeparatePatches(issue, rpc_server, patchset, data, options):
  """Uploads a separate patch for each file in the diff output.

  Returns a list of [patch_key, filename] for each file.
  """
  patches = SplitPatch(data)
  rv = []
  for patch in patches:
    if len(patch[1]) > MAX_UPLOAD_SIZE:
      print ("Not uploading the patch for " + patch[0] +
             " because the file is too large.")
      continue
    form_fields = [("filename", patch[0])]
    if options.local_base:
      form_fields.append(("content_upload", "1"))
    files = [("data", "data.diff", patch[1])]
    ctype, body = EncodeMultipartFormData(form_fields, files)
    url = "/%d/upload_patch/%d" % (int(issue), int(patchset))
    print "Uploading patch for " + patch[0]
    response_body = rpc_server.Send(url, body, content_type=ctype)
    lines = response_body.splitlines()
    if not lines or lines[0] != "OK":
      StatusUpdate("  --> %s" % response_body)
      sys.exit(False)
    rv.append([lines[1], patch[0]])
  return rv


def GuessVCS():
  """Helper to guess the version control system.

  This examines the current directory, guesses which VersionControlSystem
  we're using, and returns an instance of the appropriate class.  Exit with an
  error if we can't figure it out.

  Returns:
    A VersionControlSystem instance. Exits if the VCS can't be guessed.
  """
  # Subversion has a .svn in all working directories.
  if os.path.isdir('.svn'):
    logging.info("Guessed VCS = Subversion")
    return SubversionVCS()

  # Git has a command to test if you're in a git tree.
  # Try running it, but don't die if we don't have git installed.
  try:
    subproc = subprocess.Popen(["git", "rev-parse", "--is-inside-work-tree"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if subproc.wait() == 0:
      return GitVCS()
  except OSError, (errno, message):
    if errno != 2:  # ENOENT -- they don't have git installed.
      raise

  ErrorExit(("Could not guess version control system. "
             "Are you in a working copy directory?"))


def RealMain(argv, data=None):
  logging.basicConfig(format=("%(asctime).19s %(levelname)s %(filename)s:"
                              "%(lineno)s %(message)s "))
  os.environ['LC_ALL'] = 'C'
  options, args = parser.parse_args(argv[1:])
  global verbosity
  verbosity = options.verbose
  if verbosity >= 3:
    logging.getLogger().setLevel(logging.DEBUG)
  elif verbosity >= 2:
    logging.getLogger().setLevel(logging.INFO)
  vcs = GuessVCS()
  if isinstance(vcs, SubversionVCS):
    # base field is only allowed for Subversion.
    # Note: Fetching base files may become deprecated in future releases.
    base = vcs.GuessBase(not options.local_base)
  else:
    base = None
  if not base and not options.local_base:
    options.local_base = True
    logging.info("Enabled upload of base file")
  if not options.assume_yes:
    vcs.CheckForUnknownFiles()
  if data is None:
    data = vcs.GenerateDiff(args)
  if verbosity >= 1:
    print "Upload server:", options.server, "(change with -s/--server)"
  if options.issue:
    prompt = "Message describing this patch set: "
  else:
    prompt = "New issue subject: "
  message = options.message or raw_input(prompt).strip()
  if not message:
    ErrorExit("A non-empty message is required")
  rpc_server = GetRpcServer(options)
  form_fields = [("subject", message)]
  if base:
    form_fields.append(("base", base))
  if options.issue:
    form_fields.append(("issue", str(options.issue)))
  if options.email:
    form_fields.append(("user", options.email))
  if options.reviewers:
    for reviewer in options.reviewers.split(','):
      if reviewer.count("@") != 1 or "." not in reviewer.split("@")[1]:
        ErrorExit("Invalid email address: %s" % reviewer)
    form_fields.append(("reviewers", options.reviewers))
  if options.cc:
    for cc in options.cc.split(','):
      if cc.count("@") != 1 or "." not in cc.split("@")[1]:
        ErrorExit("Invalid email address: %s" % cc)
    form_fields.append(("cc", options.cc))
  description = options.description
  if options.description_file:
    if options.description:
      ErrorExit("Can't specify description and description_file")
    file = open(options.description_file, 'r')
    description = file.read()
    file.close()
  if description:
    form_fields.append(("description", description))
  # If we're uploading base files, don't send the email before the uploads, so
  # that it contains the file status.
  if options.send_mail and not options.local_base:
    form_fields.append(("send_mail", "1"))
  if options.local_base:
    form_fields.append(("content_upload", "1"))
  if len(data) > MAX_UPLOAD_SIZE:
    print "Patch is large, so uploading file patches separately."
    files = []
    form_fields.append(("separate_patches", "1"))
  else:
    files = [("data", "data.diff", data)]
  ctype, body = EncodeMultipartFormData(form_fields, files)
  response_body = rpc_server.Send("/upload", body, content_type=ctype)
  if options.local_base or not files:
    lines = response_body.splitlines()
    if len(lines) >= 2:
      msg = lines[0]
      patchset = lines[1].strip()
      patches = [x.split(" ", 1) for x in lines[2:]]
    else:
      msg = response_body
  else:
    msg = response_body
  StatusUpdate(msg)
  if not response_body.startswith("Issue created.") and \
  not response_body.startswith("Issue updated."):
    sys.exit(0)
  issue = msg[msg.rfind("/")+1:]

  if not files:
    result = UploadSeparatePatches(issue, rpc_server, patchset, data, options)
    if options.local_base:
      patches = result

  if options.local_base:
    vcs.UploadBaseFiles(issue, rpc_server, patches, patchset, options)
    if options.send_mail:
      rpc_server.Send("/" + issue + "/mail")
  return issue


def main():
  try:
    RealMain(sys.argv)
  except KeyboardInterrupt:
    print
    StatusUpdate("Interrupted.")
    sys.exit(1)


if __name__ == "__main__":
  main()
