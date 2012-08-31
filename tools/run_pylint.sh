#!/bin/sh
# Runs pylint on all python files in codereview/
#
# Skips over 'cpplint' which is a third part in the chromium branch.
#
ROOT=$(dirname $(readlink -f $0))/..
GAE=$ROOT/../google_appengine
FILES=$(find codereview -iname "*.py" | grep -v "cpplint")
IMPORTS=$GAE:$GAE/lib/django_1_2
PYTHONPATH=$IMPORTS:$PYTHONPATH pylint $FILES
