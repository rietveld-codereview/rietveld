#!/usr/bin/python
#
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

"""Script to simplify some common AppEngine actions.

Use 'rietveld help' for a list of commands.
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import zipfile


APPCFG = 'appcfg.py'
DEV_APPSERVER = 'dev_appserver.py'
RELEASE = 'release'
ZIPFILE = 'django.zip'
FILES = ["app.yaml", "index.yaml", "__init__.py", "main.py", "settings.py"]
DIRS = ["static", "templates", "codereview"]
IGNORED_DIR = (".svn", "gis", "admin", "localflavor", "mysql", "mysql_old",
               "oracle", "postgresql", "postgresql_psycopg2", "sqlite3",
               "test")
IGNORED_EXT = (".pyc", ".pyo", ".po", ".mo")


def ErrorExit(msg):
  """Print an error message to stderr and exit."""
  print >>sys.stderr, msg
  sys.exit(1)


# Use a shell for subcommands on Windows to get a PATH search.
use_shell = sys.platform.startswith("win")


def RunShell(command, print_output=False):
  """Executes a command and returns the output."""
  p = subprocess.Popen(command, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, shell=use_shell)
  output = ""
  while True:
    line = p.stdout.readline()
    if not line:
      break
    if print_output:
      print line.strip('\n')
    output += line
  p.wait()
  p.stdout.close()
  return output


def Help():
  print "Available commands:"
  print "help"
  print "release"
  print "serve"
  print "serve_email"
  print "serve_remote"
  print "serve_remote_email"
  print "update"
  print "update_indexes"
  print "upload"
  print "vacuum_indexes"


def CreateRelease():
  """ Creates a "release" subdirectory.

  This is a subdirectory containing a bunch of symlinks, from which the app can
  be updated.  The main reason for this is to import Django from a zipfile,
  which saves dramatically in upload time: statting and computing the SHA1 for
  1000s of files is slow.  Even if most of those files don't actually need to
  be uploaded, they still add to the work done for each update.
  """

  def GetDjangoFiles():
    """Return a list of Django files to send to the server.

    We prune:
     - .svn subdirectories for obvious reasons.
     - the other directories are huge and unneeded.
     - *.po and *.mo files because they are bulky and unneeded.
     - *.pyc and *.pyo because they aren't used by App Engine anyway.
    """
    result = []
    for root, dirs, files in os.walk("django"):
      dirs[:] = [d for d in dirs if d not in IGNORED_DIR]
      for file in files:
        unused, extension = os.path.splitext(file)
        if extension in IGNORED_EXT:
          continue
        result.append(os.path.join(root, file))
    return result

  def CopyRietveldDirectory(src, dst):
    """Copies a directory used by Rietveld.

    Skips ".svn" directories and ".pyc" files.
    """
    for root, dirs, files in os.walk(src):
      if not os.path.exists(os.path.join(dst, root)):
        os.mkdir(os.path.join(dst, root))
      for file in files:
        unused, extension = os.path.splitext(file)
        if extension in (".pyc", ".pyo"):
          continue
        shutil.copyfile(os.path.join(root, file), os.path.join(dst, root, file))
      dirs[:] = [d for d in dirs if d not in (".svn")]
      for dir in dirs:
        os.mkdir(os.path.join(dst, root, dir))

  # Remove old ZIPFILE file.
  if os.path.exists(ZIPFILE):
    os.remove(ZIPFILE)

  django_files = GetDjangoFiles()
  django_zip = zipfile.ZipFile(ZIPFILE, "w")
  for file in django_files:
    django_zip.write(file, compress_type=zipfile.ZIP_DEFLATED)
  django_zip.close()

  # Remove old RELEASE directory.
  if sys.platform.startswith("win"):
    RunShell(["rmdir", "/s", "/q", RELEASE])
  else:
    RunShell(["rm", "-rf", RELEASE])

  # Create new RELEASE directory.
  os.mkdir(RELEASE)

  if sys.platform.startswith("win"):
    # No symbolic links on Windows, just copy.
    for x in FILES + [ZIPFILE]:
      shutil.copyfile(x, os.path.join(RELEASE, x))
    for x in DIRS:
      CopyRietveldDirectory(x, RELEASE)
  else:
    # Create symbolic links.
    for x in FILES + DIRS + [ZIPFILE]:
      RunShell(["ln", "-s", "../" + x, os.path.join(RELEASE, x)])


def GetApplicationName():
  file = open("app.yaml", "r")
  result = file.read()
  file.close()
  APP_REGEXP = ".*?application: ([\w\-]+)"
  return re.compile(APP_REGEXP, re.DOTALL).match(result).group(1)


def Update(args):
  print "Updating " + GetApplicationName()
  output = RunShell(["svn", "info"])
  revision = re.compile(".*?\nRevision: (\d+)",
                        re.DOTALL).match(output).group(1)
  revision_file = os.path.join("templates", "live_revision.html")
  file = open(revision_file, "w")
  file.write('This is <a class="novisit" '
             'href="http://code.google.com/p/rietveld/">Rietveld</a> r' +
             revision)
  file.close()
  CreateRelease()
  appcfg_args = [APPCFG, "update", RELEASE] + args
  # Use os.system here because input might be required, and that doesn't work
  # through subprocess.Popen.
  os.system(" ".join(appcfg_args))
  RunShell(["svn", "revert", revision_file])


def main(argv=None):
  if argv is None:
    argv = sys.argv

  if len(argv) == 1:
    Help()
    return 0

  command = argv[1]
  if command == "help":
    Help()
  elif command == "serve":
    RunShell([DEV_APPSERVER, "."], True)
  elif command == "serve_remote":
    RunShell([DEV_APPSERVER, "--address", "0.0.0.0", "."], True)
  elif command == "serve_email":
    RunShell([DEV_APPSERVER, "--enable_sendmail", "."], True)
  elif command == "serve_remote_email":
    RunShell([DEV_APPSERVER, "--enable_sendmail", "--address", "0.0.0.0", "."],
             True)
  elif command == "release":
    CreateRelease()
  elif command in ("update", "upload"):
    Update(argv[2:])
  elif command == "update_indexes":
    RunShell([APPCFG, "update_indexes", "."], True)
  elif command == "vacuum_indexes":
    RunShell([APPCFG, "vacuum_indexes", "."], True)
  else:
    print "Unknown command: " + command
    return 2

  return 0


if __name__ == "__main__":
    sys.exit(main())
