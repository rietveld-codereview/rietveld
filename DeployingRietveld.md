# Deploying Rietveld #

This page describes how to set up a custom instance of the codereview server.
It's assumed that you've a already signed up for an [App Engine account](http://code.google.com/appengine/) and that you have [registered an application](http://code.google.com/appengine/docs/python/gettingstarted/uploading.html).

Refer to [Using Code Reviews with Google Apps](http://code.google.com/p/rietveld/wiki/CodeReviewHelp#Using_Code_Reviews_with_Google_Apps) if you are an Google Apps customer.

To set up your own instance of the codereview server you'll need to following tools:

  * [Python 2.7](http://python.org)
  * [App Engine SDK](http://code.google.com/appengine/downloads.html)
  * [Mercurial](http://mercurial.selenic.com/)

#### Getting the Sources ####

First you'll have to check out the current source from the project's Mercurial repository:

```
hg clone http://code.google.com/p/rietveld
```

#### Configure Your Application ####

Now change into the _rietveld_ directory and open `app.yaml` to configure your application ID. To do that replace _codereview_ in the first line with your ID, for example:

```
application: your-application-id
```

#### Deploy Rietveld ####

To deploy Rietveld on App Engine you'll have to use make:

```
make update
```

In case `make` is not installed on your system, read the contents of Makefile for what to do (the Makefile is mostly just used as a shorthand, there's nothing to build).

Your own instance of the codereview server should now be ready for serving on `http://your-application-id.appspot.com`.


#### Enabling OAuth2 ####

Note: OAuth2 authentication is not fully implemented at the moment.

In the following steps the URL "codereview.appspot.com" is used. Please change
it to the URL under which your Rietveld instance is installed.

In order for OAuth to work, you'll need to

  1. Create a project on https://code.google.com/apis/console/.
  1. Go down to the "API Access" tab and click "Create an OAuth2 Client ID"
  1. On the "Branding Information" page, in "Product Name", make it clear that this is for your instance, for example by adding "codereview.appspot.com". The rest is optional, then click "Next".
  1. Select type "Web application", for the "site" add the URL under which the Rietveld instance is installed and click "Create Client ID".
  1. Make sure "Redirect URIs" is set to  "https://codereview.appspot.com/oauth2callback"
  1. Copy the "Client ID" and "Client Secret" you just created.
  1. Visit https://codereview.appspot.com/restricted/set-client-id-and-secret and add them to the application.

A few other side notes:

  * Steps 1-5 are mostly described in  https://developers.google.com/console/help/#creatingdeletingprojects
  * You can click the "Team" tab on the left to add other Owners/Contributors to your Google APIs Project.


#### Security ####

By default anyone can view issues on a Rietveld instance without logging in.
To force uses to log in to view issues change

```
- url: /.*
  script: main.application
```

to

```
- url: /.*
  script: main.application
  login: required
```

in `app.yaml`.

Another default is that Rietveld always uses SSL. If you haven't setup SSL
for your appspot instance or custom domain, do so! Additional information
on how to set up SSL are described in https://developers.google.com/appengine/docs/ssl.
If you really don't want to use secure connections you need to change `MIDDLEWARE_CLASSES` in `settings.py` and comment to both classes that are responsible for the redirects as shown in the following example:

```
MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    # 'codereview.middleware.RedirectToHTTPSMiddleware',
    # 'codereview.middleware.AddHSTSHeaderMiddleware',
    'codereview.middleware.AddUserToRequestMiddleware',
    'codereview.middleware.PropagateExceptionMiddleware',
)
```

See also [[Upgrading](Upgrading.md)]