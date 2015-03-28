#### Key point revisions ####

These are revisions after which you won't be able to rollback to earlier versions. Please add an explanation to each one.

> [r1396a70e1255](https://code.google.com/p/rietveld/source/detail?r=1396a70e12552646e36e6f8efda26f74e61d8897) - make db.Email -> db.String for further migration to NDB

#### Migrations ####

These revisions require migration steps. Please ask
on the [mailing list](http://groups.google.com/group/codereview-discuss) if you need help.

Note that that running data migrations usually changes the
modified date for certain entities.

  * [r427](https://code.google.com/p/rietveld/source/detail?r=427) (yyyy-mm-dd): Issue.private field introduced with `False` as default. All issues need to be updated with `issue.private = False`, otherwise the issues a treated as private issues.