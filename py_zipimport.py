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

"""Pure Python zipfile importer.

This approximates the standard zipimport module, which isn't supported
by Google App Engine.  See PEP 302 for more information about the API
for import hooks.

Usage:
  import py_zipimport

As a side effect of importing, the module overrides sys.path_hooks,
and also creates an alias 'zipimport' for itself.  When your app is
running in Google App Engine production, you don't even need to import
it, since this is already done for you.  In the Google App Engine SDK
this module is not used; instead, the standard zipimport module is
used.
"""

__author__ = ('Iain Wade', 'Guido van Rossum')

__all__ = ['ZipImportError', 'zipimporter']

# NOTE(guido): Because this module is imported really early, importing
# logging here is somehow a bad idea for the Python runtime, and
# causes TestLogging to fail with a bizarre error condition.  Instead,
# we import logging when it's actually needed (there are two places
# where we log something).  There are also a few commented-out
# logging.debug() calls which may serve a purpose for debugging this
# under the SDK.  To enable those, simply replace all occurrences of
# '##' with '' in this file.

##import logging
import os
import sys
import types
import zipfile


# Order in which we probe the zipfile directory.
# This is a list of (suffix, is_package) tuples.
_SEARCH_ORDER = [
    # Try .py first since that is most common.
    ('.py', False),
    ('/__init__.py', True),
]


# Cache for opened zipfiles.
# Maps zipfile pathnames to zipfile.ZipFile instances.
_zipfile_cache = {}


class ZipImportError(ImportError):
  """Exception raised by zipimporter objects."""


# The class name is all lowercase to be compatible with standard zipimport.
class zipimporter:
  """A PEP-302-style importer that can import from a zipfile.

  Just insert or append this class (not an instance) to sys.path_hooks
  and you're in business.  Instances satisfy both the 'importer' and
  'loader' APIs specified in PEP 302.
  """

  def __init__(self, path_entry):
    """Constructor.

    Args:
      path_entry: The entry in sys.path.  This should be the name of an
        existing zipfile possibly with a path separator and a prefix
        path within the archive appended, e.g. /x/django.zip or
        /x/django.zip/foo/bar.

    Raises:
      ZipImportError if the path_entry does not represent a valid
      zipfile with optional prefix.
    """
    # Analyze the path_entry.
    archive = path_entry
    prefix = ''
    # Strip trailing sections until an existing path is found
    while not os.path.lexists(archive):
      head, tail = os.path.split(archive)
      if head == archive:
        msg = 'Nothing found for %r' % path_entry
        ##logging.debug(msg)
        raise ZipImportError(msg)
      archive = head
      prefix = os.path.join(tail, prefix)
    if not os.path.isfile(archive):
      msg = 'Non-file %r found for %r' % (archive, path_entry)
      ##logging.debug(msg)
      raise ZipImportError(msg)
    # Initialize the zipimporter instance.
    self.archive = archive
    self.prefix = os.path.join(prefix, '')
    # Try to get the zipfile from the cache.
    self.zipfile = _zipfile_cache.get(archive)
    if self.zipfile is None:
      # Open the zip file and read the index.
      try:
        self.zipfile = zipfile.ZipFile(self.archive)
      except (EnvironmentError, zipfile.BadZipfile), err:
        # This is logged as a warning since it means we failed to open
        # what appears to be an existing zipfile.
        msg = 'Can\'t open zipfile %s: %s: %s' % (self.archive,
                                                  err.__class__.__name__, err)
        import logging
        logging.warn(msg)
        raise ZipImportError(msg)
      else:
        # Update the cache.
        _zipfile_cache[archive] = self.zipfile
        # This is logged as info since it represents a significant
        # result.  This log message appears only during the initial
        # process initialization, not for subsequent requests.
        import logging
        logging.info('zipimporter(%r, %r)', archive, prefix)

  def __repr__(self):
    """Return a string representation matching zipimport.c."""
    name = self.archive
    if self.prefix:
      name = os.path.join(name, self.prefix)
    return '<zipimporter object "%s">' % name

  def _get_info(self, fullmodname):
    """Internal helper for find_module() and load_module().

    Args:
      fullmodname: The dot-separated full module name, e.g. 'django.core.mail'.

    Returns:
      A tuple (submodname, is_package, relpath) where:
        submodname: The final component of the module name, e.g. 'mail'.
        is_package: A bool indicating whether this is a package.
        relpath: The path to the module's source code within to the zipfile.

    Raises:
      ImportError if the module is not found in the archive.
    """
    parts = fullmodname.split('.')
    submodname = parts[-1]
    for suffix, is_package in _SEARCH_ORDER:
      relpath = os.path.join(self.prefix, submodname + suffix)
      try:
        self.zipfile.getinfo(relpath)
      except KeyError:
        pass
      else:
        return submodname, is_package, relpath
    msg = ('Can\'t find module %s in zipfile %s with prefix %r' %
           (fullmodname, self.archive, self.prefix))
    ##logging.debug(msg)
    raise ZipImportError(msg)

  def _get_source(self, fullmodname):
    """Internal helper for load_module().

    Args:
      fullmodname: The dot-separated full module name, e.g. 'django.core.mail'.

    Returns:
      A tuple (submodname, is_package, fullpath, source) where:
        submodname: The final component of the module name, e.g. 'mail'.
        is_package: A bool indicating whether this is a package.
        fullpath: The path to the module's source code including the
          zipfile's filename.
        source: The module's source code.

    Raises:
      ImportError if the module is not found in the archive.
    """
    submodname, is_package, relpath = self._get_info(fullmodname)
    fullpath = '%s/%s' % (self.archive, relpath)
    source = self.zipfile.read(relpath)
    source = source.replace('\r\n', '\n')
    source = source.replace('\r', '\n')
    return submodname, is_package, fullpath, source

  def find_module(self, fullmodname, path=None):
    """PEP-302-compliant find_module() method.

    Args:
      fullmodname: The dot-separated full module name, e.g. 'django.core.mail'.
      path: Optional and ignored; present for API compatibility only.

    Returns:
      None if the module isn't found in the archive; self if it is found.
    """
    try:
      submodname, is_package, relpath = self._get_info(fullmodname)
    except ImportError:
      ##logging.debug('find_module(%r) -> None', fullmodname)
      return None
    else:
      ##logging.debug('find_module(%r) -> self', fullmodname)
      return self

  def load_module(self, fullmodname):
    """PEP-302-compliant load_module() method.

    Args:
      fullmodname: The dot-separated full module name, e.g. 'django.core.mail'.

    Returns:
      The module object constructed from the source code.

    Raises:
      SyntaxError if the module's source code is syntactically incorrect.
      ImportError if there was a problem accessing the source code.
      Whatever else can be raised by executing the module's source code.
    """
    ##logging.debug('load_module(%r)', fullmodname)
    submodname, is_package, fullpath, source = self._get_source(fullmodname)
    code = compile(source, fullpath, 'exec')
    mod = sys.modules.get(fullmodname)
    if mod is None:
      mod = sys.modules[fullmodname] = types.ModuleType(fullmodname)
    mod.__loader__ = self
    mod.__file__ = fullpath
    mod.__name__ = fullmodname
    if is_package:
      mod.__path__ = [os.path.dirname(mod.__file__)]
    exec code in mod.__dict__
    return mod

  # Optional PEP 302 functionality.  See the PEP for specs.

  def get_data(self, fullpath):
    """Return (binary) content of a data file in the zipfile."""
    required_prefix = os.path.join(self.archive, '')
    if not fullpath.startswith(required_prefix):
      raise IOError('Path %r doesn\'t start with zipfile name %r' %
                    (fullpath, required_prefix))
    relpath = fullpath[len(required_prefix):]
    try:
      return self.zipfile.read(relpath)
    except KeyError:
      raise IOError('Path %r not found in zipfile %r' %
                    (relpath, self.archive))

  def is_package(self, fullmodname):
    """Return whether a module is a package."""
    submodname, is_package, relpath = self._get_info(fullmodname)
    return is_package

  def get_code(self, fullmodname):
    """Return bytecode for a module."""
    submodname, is_package, fullpath, source = self._get_source(fullmodname)
    return compile(source, fullpath, 'exec')

  def get_source(self, fullmodname):
    """Return source code for a module."""
    submodname, is_package, fullpath, source = self._get_source(fullmodname)
    return source


# Install our hook.
##logging.debug("%s: installing sys.path_hooks", __name__)
sys.modules['zipimport'] = sys.modules[__name__]
sys.path_hooks[:] = [zipimporter]
