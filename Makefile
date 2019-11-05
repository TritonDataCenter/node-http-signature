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


include ./tools/mk/Makefile.deps
include ./tools/mk/Makefile.targ
