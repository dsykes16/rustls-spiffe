# Makefile for building spire-server and spire-agent from a versioned tarball.
# Usage:
#   make SPIRE_VERSION=1.11.2
#   make clean
#   make distclean

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

# ==== Configuration ====
SPIRE_VERSION ?= 1.13.1
TARBALL_URL   := https://github.com/spiffe/spire/archive/refs/tags/v$(SPIRE_VERSION).tar.gz

# Directories
BUILD_DIR  := build
BIN_DIR    := bin

# Artifacts & stamps
TARBALL        := $(BUILD_DIR)/spire-$(SPIRE_VERSION).tar.gz
SRC_DIR        := $(BUILD_DIR)/spire-$(SPIRE_VERSION)
EXTRACT_STAMP  := $(BUILD_DIR)/.extracted-spire-$(SPIRE_VERSION)
VERSION_STAMP  := $(BIN_DIR)/.spire-version

SERVER_BIN := $(BIN_DIR)/spire-server
AGENT_BIN  := $(BIN_DIR)/spire-agent

# Tools (prefer curl, fallback to wget)
CURL := $(shell command -v curl 2>/dev/null)
WGET := $(shell command -v wget 2>/dev/null)
ifeq ($(CURL),)
  ifeq ($(WGET),)
    $(error Neither 'curl' nor 'wget' found in PATH)
  else
    DOWNLOADER = wget -O
  endif
else
  DOWNLOADER = curl -fL -o
endif

# Make setup
.ONESHELL:
.DELETE_ON_ERROR:
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

.PHONY: all clean distclean verify

all: $(SERVER_BIN) $(AGENT_BIN)

# Record the requested version; only update timestamp if content changes.
# This makes binaries rebuild when SPIRE_VERSION changes, but NOT otherwise.
$(VERSION_STAMP):
	@mkdir -p $(BIN_DIR)
	@echo "$(SPIRE_VERSION)" | cmp -s - $@ || echo "$(SPIRE_VERSION)" > $@

# Download tarball for the specified version.
$(TARBALL):
	@mkdir -p $(BUILD_DIR)
	@echo "==> Downloading SPIRE v$(SPIRE_VERSION)"
	@$(DOWNLOADER) $@ "$(TARBALL_URL)"

# Extract once and drop a fresh stamp so binaries depend only on this (not every file).
$(EXTRACT_STAMP): $(TARBALL)
	@echo "==> Extracting SPIRE v$(SPIRE_VERSION)"
	@rm -rf "$(SRC_DIR)"
	@tar -xzf "$(TARBALL)" -C "$(BUILD_DIR)"
	@# Ensure the extracted directory matches expected name (GitHub tarball does).
	@test -d "$(SRC_DIR)"
	@touch "$(EXTRACT_STAMP)"

# Build binaries (avoid rebuilds if up-to-date)
$(SERVER_BIN): $(EXTRACT_STAMP) $(VERSION_STAMP)
	@echo "==> Building $@ from SPIRE v$(SPIRE_VERSION)"
	@cd "$(SRC_DIR)" && go build -o "$(abspath $@)" ./cmd/spire-server

$(AGENT_BIN): $(EXTRACT_STAMP) $(VERSION_STAMP)
	@echo "==> Building $@ from SPIRE v$(SPIRE_VERSION)"
	@cd "$(SRC_DIR)" && go build -o "$(abspath $@)" ./cmd/spire-agent

# Optional: quick sanity check that the built binaries run (prints version)
verify: $(SERVER_BIN) $(AGENT_BIN)
	@echo "==> Verifying binaries"
	@$(SERVER_BIN) --version || { echo "ERROR: spire-server binary not ok"; }
	@$(AGENT_BIN) --version  || { echo "ERROR: spire-agent binary not ok"; }

# Clean built binaries only
clean:
	@echo "==> Cleaning binaries"
	@rm -f "$(SERVER_BIN)" "$(AGENT_BIN)"
	@rm -rf "$(BIN_DIR)"

# Remove everything including downloads and extracted sources
distclean: clean
	@echo "==> Removing build artifacts"
	@rm -rf "$(BUILD_DIR)" "$(VERSION_STAMP)"
