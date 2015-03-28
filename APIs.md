# Introduction #

Rietveld has several APIs that were added over time. Here's a short
overview. As every doc, this page won't be up to date so make sure to
take a look at [urls.py](http://code.google.com/p/rietveld/source/browse/codereview/urls.py) which contains all rietveld's url entry points and [views.py](http://code.google.com/p/rietveld/source/browse/codereview/views.py) for the actual implementation, and of course [edit this page](http://code.google.com/p/rietveld/source/browse/APIs.wiki?repo=wiki&edit=1) to fill missing info.

## Libraries and Tools ##

Mercurial extension that wraps `upload.py` functionality into `hg review ` command, by Nicolas Évrard:
  * https://pypi.python.org/pypi/hgreview/

Some third party libraries that provide language specific interface to the web APIs:

  * Go - http://godoc.org/launchpad.net/goetveld/rietveld

# Reading #

## Issue details as JSON ##
```
/api/<issue>/
```

Returns metadata about an issue encoded in JSON **without the actual patch**. Private issues require an authentication cookie in the GET request. Query parameter supported is:
  * `messages=true` will includes all messages posted on the issue.

See implementation in [\_issue\_as\_dict()](http://www.google.com/codesearch?q=package%3Ahttp%3A%2F%2Frietveld%5C.googlecode%5C.com+_issue_as_dict) for the included metadata.


## Patchset details as JSON ##
```
/api/<issue>/<patchset>
```

Returns metadata about a specific patchset encoded in JSON **without the actual patch**. Private issues require an authentication cookie in the GET request.

See implementation in [\_patchset\_as\_dict()](http://www.google.com/codesearch?q=package%3Ahttp%3A%2F%2Frietveld%5C.googlecode%5C.com+_patchset_as_dict) for the included metadata.


## Searching for issues by properties ##
```
/search
```

GET request returns the web form. The actual search is performed on POST request. Private issues will be included if the POST request has an authentication cookie, no XSRF token is needed. Query parameters supported are:

  * `format=json` will make `/search` return the data as **JSON** instead of the default web page (use `json_pretty` to get more beautiful output instead of the default compact representation)
  * `keys_only=true` can be used to speed up search when the actual data is not needed.
  * `limit=<0-1000>` can be used to limit the number of returned values. The default is 100.
  * `cursor=<cookie>` permits continuing a search query by setting the cursor query parameter to the value returned by the previous result. This permits iterating over an infinite number of elements.
  * `with_messages=true` will include all messages posted on the issues.
  * All other query parameters included when using the web form.

See implementation details in [search()](http://www.google.com/codesearch?q=package%3Ahttp%3A%2F%2Frietveld%5C.googlecode%5C.com+"def+search").

**Note:** Some request may require adding yet another index in
[index.yaml](http://code.google.com/p/rietveld/source/browse/index.yaml).

# Writing #

## Authentication ##
```
/xsrf_token
```

Unlike reading APIs, writing APIs require authentication _and_ an XSRF
token. So you first need to do a POST request to `/xsrf_token` to get the
XSRF token. By doing that, you will be redirected to login page, where
the script can prompt the user for authentication credentials. See
[upload.py](http://code.google.com/p/rietveld/source/browse/upload.py) for an example of authenticated API usage.

## Simple commands ##
```
/<issue>/close
/<issue>/delete
/<issue>/fields  ->  Set or get a field on an issue
/<issue>/patchset/<patchset>/delete
/<issue>/publish
/<issue>/star
/<issue>/unstar
```
Most of them are really simple. I simply recommend to figure out the
function name of implementation in
[urls.py](http://code.google.com/p/rietveld/source/browse/codereview/urls.py) and then read their implementation in
[views.py](http://code.google.com/p/rietveld/source/browse/codereview/views.py).

# Something's missing? #
Please [contribute](Contributing.md) it!