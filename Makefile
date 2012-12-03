# Makefile to simplify some common AppEngine actions.
# Use 'make help' for a list of commands.

APPID?= `cat app.yaml | sed -n 's/^application: *//p'`

SDK_PATH ?=

DEV_APPSERVER?= $(if $(SDK_PATH), $(SDK_PATH)/,)dev_appserver.py
DEV_APPSERVER_FLAGS?=

APPCFG?= $(if $(SDK_PATH), $(SDK_PATH)/,)appcfg.py
APPCFG_FLAGS?=

# Set dirty suffix depending on output of "hg status".
dirty=
ifneq ($(shell hg status),)
        dirty="-tainted"
endif
VERSION_TAG= `hg parents --template='{rev}:{node|short}'`$(dirty)
# AppEngine version cannot use ':' in its name so use a '-' instead.
VERSION?= `hg parents --template='{rev}-{node|short}'`$(dirty)

PYTHON?= python2.7
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
	@echo "$(VERSION_TAG)" >REVISION

update: update_revision
	@echo "---[Updating $(APPID)]---"
	$(APPCFG) $(APPCFG_FLAGS) update . --application $(APPID) --version $(VERSION)

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
