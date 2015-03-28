#### LGTM, PTAL? ####

"Looks good to me", "Please take a look".

#### Why isn't there a shortcut for starting a review? ####

For a list of shortcuts, press "`?`". To start review from issue page hit "o"
or "Enter". This opens side-by-side view for the currently selected file and patchset.
Note that this differs from clicking on the "Start Review", which always open view for the first file of the latest patchset.


#### I'm using TortoiseSVN on Windows, but upload.py doesn't work. What's wrong? ####

upload.py doesn't work nicely with the "svn" command provided by
TortoiseSVN. With other Subversion clients upload.py should work as
expected.

#### How can I upload a patch from Mercurial Queue? ####

Patch from Mercurial queue applied with `hg qpush` is an ordinary Mercurial changeset with revision number. Make sure the patchset is applied, and pass changeset revision range to 'hg diff' command through `--rev` option.

```
python upload.py --rev "qtip^1:qtip"
```

`qtip` references to the last applied patch from queue, `qip^1` is its first parent. It is also possible to reference to any applied patch from the queue by name. Just make sure the name is properly double-escaped.

```
python upload.py -i 10733047 --rev "'css-cleanup'^1:'css-cleanup'"
```

This command updates Rietveld [review issue 10733047](https://codereview.appspot.com/10733047/) with refreshed content from applied `css-cleanup` patch.


#### Can I use upload.py behind a proxy? ####

Yes, you can use upload.py behind a proxy. By default the list of
proxies is read from the environment variables or retrieved from your
system's proxy configuration.