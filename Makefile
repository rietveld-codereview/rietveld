# Makefile to simplify some common AppEngine actions.
# Use 'make help' for a list of commands.

SDK_PATH ?=

DEV_APPSERVER?= $(if $(SDK_PATH), $(SDK_PATH)/,)dev_appserver.py
DEV_APPSERVER_FLAGS?=

APPCFG?= $(if $(SDK_PATH), $(SDK_PATH)/,)appcfg.py
APPCFG_FLAGS?=

PYTHON?= python2.5
COVERAGE?= coverage


default: help

help:
	@echo "Available commands:"
	@sed -n '/^[a-zA-Z0-9_.]*:/s/:.*//p' <Makefile | sort

run: serve

serve: update_revision
	@echo "---[Starting SDK AppEngine Server]---"
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) .

serve_remote: update_revision
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) --address 0.0.0.0 .

serve_email: update_revision
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) --enable_sendmail .

serve_remote_email: update_revision
	$(DEV_APPSERVER) $(DEV_APPSERVER_FLAGS) --enable_sendmail --address 0.0.0.0 .

update_revision:
	@echo "---[Updating REVISION]---"
	@echo "`hg id -n`:`hg id -i`" >REVISION

update: update_revision
	@echo "---[Updating `cat app.yaml | sed -n 's/^application: *//p'`]---"
	$(APPCFG) $(APPCFG_FLAGS) update . --version $(VERSION)

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
