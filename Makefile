# Makefile to simplify some common AppEngine actions.
# Use 'make help' for a list of commands.

DEV_APPSERVER=	dev_appserver.py
APPCFG=	appcfg.py

default: help

help:
	@echo "Available commands:"
	@sed -n '/^[a-zA-Z0-9_.]*:/s/:.*//p' <Makefile | sort

serve:
	$(DEV_APPSERVER) .

serve_remote:
	$(DEV_APPSERVER) --address 0.0.0.0 .

serve_email:
	$(DEV_APPSERVER) --enable_sendmail .

serve_remote_email:
	$(DEV_APPSERVER) --enable_sendmail --address 0.0.0.0 .

release: make_release.sh django/.svn
	sh make_release.sh

update: release
	@echo "Updating `cat app.yaml | sed -n 's/^application: *//p'`"
	@echo "This is Rietveld r`svn info | sed -n 's/^Revision: *//p'`" \
		>templates/live_revision.html
	$(APPCFG) update release
	@svn revert templates/live_revision.html

upload: update

update_indexes:
	$(APPCFG) update_indexes .

vacuum_indexes:
	$(APPCFG) vacuum_indexes .
