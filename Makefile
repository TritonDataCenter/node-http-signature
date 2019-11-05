#
# Copyright 2019 Joyent, Inc.
#

JS_FILES	:= $(shell find lib -name '*.js')
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE   = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS    = -f tools/jsstyle.conf

# This, and the includes below, provide: 'make check' and 'make clean'.
include ./tools/mk/Makefile.defs


#
# Repo-specific targets
#
.PHONY: all
all: $(REPO_DEPS)
	npm install

CLEAN_FILES += ./node_modules

.PHONY: test
test: all
	TAP=1 ./node_modules/.bin/tap test/*.test.js

# Ensure CHANGES.md and package.json have the same version.
.PHONY: check-version
check-version:
	@echo version is: $(shell cat package.json | json version)
	[ "`cat package.json | json version`" = "`grep '^## ' CHANGES.md | head -2 | tail -1 | awk '{print $$2}'`" ]

check: check-version

.PHONY: cutarelease
cutarelease: $(COMPLETION_FILE) check-version
	[ -z "`git status --short`" ]  # If this fails, the working dir is dirty.
	@which json 2>/dev/null 1>/dev/null && \
	    ver=$(shell json -f package.json version) && \
	    name=$(shell json -f package.json name) && \
	    publishedVer=$(shell npm view -j $(shell json -f package.json name)@$(shell json -f package.json version) version 2>/dev/null) && \
	    if [ -n "$$publishedVer" ]; then \
		echo "error: $$name@$$ver is already published to npm"; \
		exit 1; \
	    fi && \
	    echo "** Are you sure you want to tag and publish $$name@$$ver to npm?" && \
	    echo "** Enter to continue, Ctrl+C to abort." && \
	    read
	ver=$(shell cat package.json | json version) && \
	    date=$(shell date -u "+%Y-%m-%d") && \
	    git tag -a "v$$ver" -m "version $$ver ($$date)" && \
	    git push --tags origin && \
	    npm publish


include ./tools/mk/Makefile.deps
include ./tools/mk/Makefile.targ
