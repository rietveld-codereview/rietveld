## tl;dr ##

```
python upload.py -r albrecht.andi@googlemail.com,techtonik@gmail.com --cc=codereview-list@googlegroups.com --send_mail  
```

several small patches are better than a huge one, demo helps, [improvements](http://code.google.com/p/rietveld/source/browse/Contributing.wiki?repo=wiki&edit=1) are welcome, start with an [easy to fix](http://code.google.com/p/rietveld/issues/list?can=2&q=label%3DEasy) issue.


---



## How to improve Rietveld ##

Every change to Rietveld code goes through review process, even from committers. Here is how do we make our patches accepted faster.

### Check out the source code ###

```
hg clone https://code.google.com/p/rietveld/
cd rietveld
```

### Make it running ###
Download [AppEngine SDK](http://code.google.com/appengine/downloads.html#Google_App_Engine_SDK_for_Python). Run Rietveld locally with App Engine Launcher (Windows, MacOS) or command line on Linux:
```
# change path to AppEngine SDK
SDK_PATH=../appengine make serve
```

### Prepare a patch ###
Split it into munchable chunks if you can. 5 simple patches will be more likely accepted much-much faster than a big complex one. This requires some kind of patch queue management effort on your side, but let's hope some day we'll streamline the process.

### Execute test suite ###
Make sure that your patch didn't break anything and run the test suite:

```
python tests/run_tests.py
```

This command assumes that the App Engine SDK is found in "../google\_appengine". If you have the SDK at some other location just add the path to the App Engine SDK as a paramter to run\_tests.py.

BTW, consider to add tests that cover your changes too :)

In addition to run the tests please consider to run

```
tools/run_pylint.sh
```

This command checks for style issues and syntactical errors. You'll need [PyLint](http://pypi.python.org/pypi/pylint/) installed on your system to run this command.

### Submit patch ###
To submit, upload it to codereview.appspot.com using the
[upload.py](http://codereview.appspot.com/static/upload.py) script and add Andi (albrecht.andi@googlemail.com), Guido (gvanrossum@gmail.com) or anatoly (techtonik@gmail.com) to the list of the reviewers, for example

```
upload.py -r albrecht.andi@googlemail.com --cc=codereview-list@googlegroups.com --send_mail  
```

Make sure you're **subscribed** to [codereview-discuss](https://groups.google.com/forum/#forum/codereview-discuss) or else notification to group may bounce. If you're uploading a patch using the web based form, don't forget to use the Publish+Mail link on the issue page. To update your patch, use -i option with your issue number:

```
upload.py -i XXXXXX --send_mail
```

### Prepare a demo (optional) ###
Although it can be daunting at first, a demo _really_ helps to review your changes faster, as it allows to check if other parts of the application still work as expected. So, if your time permits, upload your patched Rietveld version to https://appspot.com with example data, and add the link to the issue description.

With the AppEngine launcher it takes less than 5 minutes to replace `rietveld` with your instance name in `app.yaml` and upload. With `appcfg.py` tool for SDK it is even easier.
```
appcfg.py update -A instancename rietvelddir/
```

For the sample data we look for a way of one click upload, so if you have ideas (or even patches) - feel free to add them to the [issue #258](https://code.google.com/p/rietveld/issues/detail?id=#258).


---


The [long list of patches](http://codereview.appspot.com/search?repo_guid=5c54f386432c6547d76465074e6ed7a64c17be69&closed=3) sent for review, the ones that are most simple, handy and have a demo are given the top priority.

At this point we have only few automated tests. These are mostly for handling emails. Everything else is less complex and is tested manually under the SDK. Code review does the rest.

### Legal stuff ###

We're living in interesting times. That's why individual contributors need to fill out the
[Individual Contributor License Agreement](http://code.google.com/legal/individual-cla-v1.0.html).  (Please use the electronic form at the bottom of the page.)
It does **not** transfer copyright, it is actually a slightly modified
version of the CLA for the Apache Software Foundation.

For Corporate contributors, there's the
[Software Grant and Corporate Contributor License Agreement](http://code.google.com/legal/corporate-cla-v1.0.html).

Google employees do **not** have to fill out one of these!

## Version numbers ##
We increment the version on http://codereview.appspot.com/ every upload and keep at least one older version on the production instance (in case we have to switch back to a version that is known to be working). `app.yaml` is changed from time to time but not on all uploads.

## Rietveld Internals ##
Some features of Rietveld that you may keep in mind, because they are different from standard Django/AppEngine applications:
  * `request.user` is always present (in standard GAE app it is not), but it may be `None` (always an object in Django if auth is enabled)
  * `request.user` is an instance of AppEngine [User()](http://code.google.com/appengine/docs/python/users/userclass.html) (if not `None`)
  * `request.user.nickname()` is never used. Rietveld uses its own nicknames stored in Account model

## Feedback ##

If you feel that the process can be improved - do not hesitate to suggest your changes for review. Thanks.