#!/bin/sh
# Runs pylint on all python files in codereview/
#
# Skips over 'cpplint' which is a third part in the chromium branch.
#
ROOT="$(dirname $(readlink -f $0))/.."
cd "$ROOT"
GAE="$ROOT/../google_appengine"
FILES=$(find codereview -iname "*.py" | grep -v "cpplint")
IMPORTS="$GAE:$GAE/lib/django-1.3:$GAE/lib/google-api-python-client"

# Disabled pylint messages:
# R0201: Method could be a function
# W0401: Wildcard import XXX
# W0614: Unused import XXX from wildcard import
DISABLED=R0201,W0401,W0614
PYTHONPATH=$IMPORTS:$PYTHONPATH pylint $FILES -d $DISABLED
