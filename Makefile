BINARY := timbuktu
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
USER    ?= $(shell id -u -n)
GOFLAGS := -ldflags="-s -w -X github.com/QYVORA/qyvora-timbuktu/internal/version.Version=$(VERSION) -X github.com/QYVORA/qyvora-timbuktu/internal/version.Commit=$(COMMIT) -X github.com/QYVORA/qyvora-timbuktu/internal/version.Date=$(DATE) -X github.com/QYVORA/qyvora-timbuktu/internal/version.BuildUser=$(USER)" -trimpath
GOFLAGS_RACE := $(GOFLAGS) -race

PREFIX ?= /usr/local
DESTDIR ?=

# --- install layout ------------------------------------------------------
# System-wide install (default PREFIX=/usr/local, typically needs root):
#   /usr/local/bin/timbuktu            command
#   /usr/local/share/applications/   desktop entry (searchable in the app menu)
#   /usr/local/share/icons/hicolor/512x512/apps/timbuktu.png
#   /usr/local/share/pixmaps/timbuktu.png
# User install (make install-user) mirrors the same layout under ~/.local.

ICON    := assets/timbuktu.png
DESKTOP := assets/timbuktu.desktop

BINDIR    := $(DESTDIR)$(PREFIX)/bin
ICONDIR   := $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps
PIXMAPDIR := $(DESTDIR)$(PREFIX)/share/pixmaps
APPDIR    := $(DESTDIR)$(PREFIX)/share/applications

USERBIN    := $(HOME)/.local/bin
USERICON   := $(HOME)/.local/share/icons/hicolor/512x512/apps
USERPIXMAP := $(HOME)/.local/share/pixmaps
USERAPP    := $(HOME)/.local/share/applications

.PHONY: all build install install-data install-user uninstall uninstall-user test test-race vet lint verify clean

all: lint vet test build

build:
	go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/timbuktu

test:
	go test ./... -count=1 -timeout 60s

test-race:
	go test -race ./... -count=1 -timeout 120s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

verify: lint vet test-race build
	@echo "ALL CHECKS PASSED"

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	$(MAKE) install-data

install-data:
	install -d $(ICONDIR) $(PIXMAPDIR) $(APPDIR)
	install -m 0644 $(ICON) $(ICONDIR)/timbuktu.png
	install -m 0644 $(ICON) $(PIXMAPDIR)/timbuktu.png
	sed -e 's|@PREFIX@|$(PREFIX)|g' $(DESKTOP) > $(APPDIR)/timbuktu.desktop
	chmod 0644 $(APPDIR)/timbuktu.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true
	@echo "timbuktu installed to $(BINDIR) with icon and desktop entry."

install-user: build
	install -d $(USERBIN)
	install -m 0755 bin/$(BINARY) $(USERBIN)/$(BINARY)
	install -d $(USERICON) $(USERPIXMAP) $(USERAPP)
	install -m 0644 $(ICON) $(USERICON)/timbuktu.png
	install -m 0644 $(ICON) $(USERPIXMAP)/timbuktu.png
	sed -e 's|@PREFIX@|$(HOME)/.local|g' $(DESKTOP) > $(USERAPP)/timbuktu.desktop
	chmod 0644 $(USERAPP)/timbuktu.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "timbuktu installed to $(USERBIN) with icon and desktop entry."
	@echo "Add $$HOME/.local/bin to your PATH if it is not already there."

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(ICONDIR)/timbuktu.png $(PIXMAPDIR)/timbuktu.png $(APPDIR)/timbuktu.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true

uninstall-user:
	rm -f $(USERBIN)/$(BINARY)
	rm -f $(USERICON)/timbuktu.png $(USERPIXMAP)/timbuktu.png $(USERAPP)/timbuktu.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true

clean:
	rm -f $(BINARY)
	rm -rf bin releases/
