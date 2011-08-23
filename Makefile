# Makefile to simplify some common AppEngine actions.
# Use 'make help' for a list of commands.

DEV_APPSERVER=	dev_appserver.py
DEV_APPSERVER_FLAGS=

APPCFG=	appcfg.py
APPCFG_FLAGS=

PYTHON= python2.5
COVERAGE= coverage
SDK_PATH=

default: help

help:
	@echo "Available commands:"
	@sed -n '/^[a-zA-Z0-9_.]*:/s/:.*//p' <Makefile | sort

serve:
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) .

serve_remote:
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) --address 0.0.0.0 .

serve_email:
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) --enable_sendmail .

serve_remote_email:
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) --enable_sendmail --address 0.0.0.0 .

update:
	@echo "Updating `cat app.yaml | sed -n 's/^application: *//p'`"
	@echo "revision `hg id -i`" >templates/live_revision.html
	$(APPCFG) $(APPCFG_FLAGS) update .
	@hg revert --no-backup templates/live_revision.html

upload: update

deploy: update

update_indexes:
	$(APPCFG) $(APPCFG_FLAGS) update_indexes .

vacuum_indexes:
	$(APPCFG) $(APPCFG_FLAGS) vacuum_indexes .

test:
	$(PYTHON) tests/run_tests.py $(SDK_PATH)

coverage:
	$(COVERAGE) run --branch tests/run_tests.py $(SDK_PATH)
	$(COVERAGE) html --include="codereview/*"