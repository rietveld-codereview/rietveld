In November 2006, I gave a public talk at Google about _Mondrian_,
a web tool for
[code review](http://en.wikipedia.org/wiki/Code_review) on the web
that I was developing at Google, for Googlers.
([Watch the video.](http://www.youtube.com/watch?v=sMql3Di4Kgc))

I've always hoped that I could release Mondrian as open source, but
it was not to be: due to its popularity inside Google, it became more
and more tied to proprietary Google infrastructure like
[Bigtable](http://labs.google.com/papers/bigtable.html),
and it remained limited to [Perforce](http://perforce.com),
the commercial revision control system most used at Google.

This application is the next best thing: an code review tool for
use with [Subversion](http://subversion.tigris.org/),
inspired by Mondrian and released as
[open source](http://code.google.com/p/rietveld/).  Some of
the code is even directly derived from Mondrian.

The open source project has the code name _Rietveld_ in honor of
[Gerrit Rietveld](http://en.wikipedia.org/wiki/Gerrit_Rietveld),
Dutch architect and furniture designer.  I've chosen to use the
more neutral [codereview](http://codereview.appspot.com) name
for the live app, since most English speakers have a hard time
typing _rietveld_ correctly.

While this web app was primarily written to serve as a showcase for
using [Django](http://djangoproject.com) with
[Google App Engine](http://code.google.com/appengine/), the
scalable infrastructure for web applications that I helped build, I
hope that it will serve as a useful tool for the open source
community, especially the [Python community](http://python.org)
to which I am so indebted.

> --Guido van Rossum, Python creator and Google employee