# Makefile to simplify some common AppEngine actions.
# Use 'make help' for a list of commands.

DEV_APPSERVER=	dev_appserver.py
APPCFG=	appcfg.py

default:
	@echo "Use 'make help' to see available commands."

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

update:
	@echo -n "This is Rietveld r" > templates/live_revision.html
	@svn info | grep '^Revision' | sed -e 's/Revision: *//' >> \
		templates/live_revision.html
	$(APPCFG) update .
	@svn revert templates/live_revision.html

upload: update

update_indexes:
	$(APPCFG) update_indexes .

vacuum_indexes:
	$(APPCFG) vacuum_indexes .
