# SPDX-License-Identifier: Apache-2.0
#
# Convenience wrapper around Meson. The real build system is meson.build;
# this Makefile just spares you from remembering the meson/ninja incantations.

BUILDDIR ?= build
PREFIX   ?= /usr/local
GUI      ?= true

MESON := meson
NINJA := ninja

.PHONY: all build configure release run run-cli install uninstall clean distclean help

all: build

## configure: create the Meson build directory
configure:
	$(MESON) setup $(BUILDDIR) --prefix=$(PREFIX) -Dgui=$(GUI)

## build: compile the project (configures first if needed)
build:
	@if [ ! -d "$(BUILDDIR)" ]; then \
		$(MESON) setup $(BUILDDIR) --prefix=$(PREFIX) -Dgui=$(GUI); \
	fi
	$(NINJA) -C $(BUILDDIR)

## release: optimized build
release:
	$(MESON) setup --reconfigure $(BUILDDIR) --prefix=$(PREFIX) \
		--buildtype=release -Dgui=$(GUI)
	$(NINJA) -C $(BUILDDIR)

## run: build and launch the GUI (needs root for the packet engine)
run: build
	sudo $(BUILDDIR)/byedpi

## run-cli: build and launch headless
run-cli: build
	sudo $(BUILDDIR)/byedpi --no-gui --verbose

## install: install system-wide (uses sudo)
install: build
	sudo $(NINJA) -C $(BUILDDIR) install

## uninstall: remove installed files
uninstall:
	sudo $(NINJA) -C $(BUILDDIR) uninstall

## clean: remove compiled objects
clean:
	@[ -d "$(BUILDDIR)" ] && $(NINJA) -C $(BUILDDIR) clean || true

## distclean: remove the whole build directory
distclean:
	rm -rf $(BUILDDIR)

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
