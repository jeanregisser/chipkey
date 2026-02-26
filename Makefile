BINARY      = chipkey
BIN_DIR     = bin
TOOLS_DIR   = $(CURDIR)/.tools
GOLANGCI_LINT = $(TOOLS_DIR)/golangci-lint
BUNDLE_ID   = com.jeanregisser.chipkey
APP_BUNDLE  = $(BIN_DIR)/Chipkey.app
APP_MACOS   = $(APP_BUNDLE)/Contents/MacOS
VERSION     ?= dev
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
APP_VERSION ?= $(VERSION)
LDFLAGS     = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Auto-detect signing identity and team ID from the keychain.
SIGN_IDENTITY ?= $(shell security find-identity -v -p codesigning | \
	awk -F'"' '/Developer ID Application/ {print $$2; exit}' 2>/dev/null)

TEAM_ID ?= $(shell echo "$(SIGN_IDENTITY)" | sed -n 's/.*(\([A-Z0-9]*\))$$/\1/p')

# Path to the provisioning profile (download from developer.apple.com).
PROVISIONING_PROFILE ?= chipkey.provisionprofile

NOTARIZE_ZIP = $(BIN_DIR)/Chipkey_$(APP_VERSION)_macos_app.zip

.PHONY: build build-darwin build-linux build-windows bundle notarize tools lint check-tidy test clean

build: build-darwin

## Build a universal macOS binary (arm64 + x86_64). Must run on macOS.
build-darwin:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-darwin-arm64 .
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-darwin-amd64 .
	lipo -create \
		-output $(BIN_DIR)/$(BINARY)-darwin \
		$(BIN_DIR)/$(BINARY)-darwin-arm64 \
		$(BIN_DIR)/$(BINARY)-darwin-amd64
	rm $(BIN_DIR)/$(BINARY)-darwin-arm64 $(BIN_DIR)/$(BINARY)-darwin-amd64

## Build Linux binaries (can cross-compile from macOS).
build-linux:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-linux-arm64 .

## Build Windows binaries (can cross-compile from macOS).
build-windows:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-windows-amd64.exe .
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-windows-arm64.exe .

## Create the .app bundle, sign it, and embed the provisioning profile.
bundle: $(BIN_DIR)/$(BINARY)-darwin
	@if [ -z "$(SIGN_IDENTITY)" ]; then \
		echo "Error: no signing identity found." >&2; exit 1; \
	fi
	@if [ -z "$(TEAM_ID)" ]; then \
		echo "Error: could not determine Team ID." >&2; exit 1; \
	fi
	@if [ ! -f "$(PROVISIONING_PROFILE)" ]; then \
		echo "Error: provisioning profile not found at $(PROVISIONING_PROFILE)" >&2; \
		echo "Download it from https://developer.apple.com/account/resources/profiles" >&2; exit 1; \
	fi
	@echo "Creating $(APP_BUNDLE) with identity: $(SIGN_IDENTITY) (Team $(TEAM_ID))"
	rm -rf $(APP_BUNDLE)
	mkdir -p $(APP_MACOS)
	cp $(BIN_DIR)/$(BINARY)-darwin $(APP_MACOS)/$(BINARY)
	sed -e 's/TEAM_ID/$(TEAM_ID)/g' entitlements.plist > $(BIN_DIR)/entitlements-resolved.plist
	sed -e 's/BUNDLE_ID/$(BUNDLE_ID)/g' \
		-e 's/APP_VERSION/$(APP_VERSION)/g' \
		-e 's/BINARY_NAME/$(BINARY)/g' \
		Info.plist > $(APP_BUNDLE)/Contents/Info.plist
	cp $(PROVISIONING_PROFILE) $(APP_BUNDLE)/Contents/embedded.provisionprofile
	codesign --force --options runtime \
		--sign "$(SIGN_IDENTITY)" \
		--entitlements $(BIN_DIR)/entitlements-resolved.plist \
		--identifier $(BUNDLE_ID) \
		$(APP_BUNDLE)
	rm $(BIN_DIR)/entitlements-resolved.plist
	@echo ""
	@echo "Bundle created: $(APP_BUNDLE)"
	@echo "Run with: $(APP_MACOS)/$(BINARY) <command>"
	@echo "Verify:   codesign -dv $(APP_BUNDLE)"

## Notarize and staple the .app bundle. Requires APPLE_ID and APPLE_APP_SPECIFIC_PASSWORD env vars.
notarize: $(APP_BUNDLE)
	@if [ -z "$(APPLE_ID)" ]; then \
		echo "Error: APPLE_ID is not set." >&2; exit 1; \
	fi
	@if [ -z "$(APPLE_APP_SPECIFIC_PASSWORD)" ]; then \
		echo "Error: APPLE_APP_SPECIFIC_PASSWORD is not set." >&2; exit 1; \
	fi
	@if [ -z "$(TEAM_ID)" ]; then \
		echo "Error: could not determine Team ID." >&2; exit 1; \
	fi
	@echo "Notarizing $(APP_BUNDLE) (Team $(TEAM_ID))..."
	zip -r "$(NOTARIZE_ZIP)" "$(APP_BUNDLE)"
	xcrun notarytool submit "$(NOTARIZE_ZIP)" \
		--apple-id "$(APPLE_ID)" \
		--password "$(APPLE_APP_SPECIFIC_PASSWORD)" \
		--team-id "$(TEAM_ID)" \
		--wait
	xcrun stapler staple "$(APP_BUNDLE)"
	rm "$(NOTARIZE_ZIP)"
	zip -r "$(NOTARIZE_ZIP)" "$(APP_BUNDLE)"
	@echo ""
	@echo "Notarized bundle zipped at: $(NOTARIZE_ZIP)"

## Install development tools into .tools/.
tools:
	@mkdir -p $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1

lint: tools
	$(GOLANGCI_LINT) run ./...

check-tidy:
	go mod tidy
	@git diff --exit-code go.mod go.sum || (echo "go.mod/go.sum not tidy — run 'go mod tidy'" >&2; exit 1)

test:
	go test -v ./...

clean:
	rm -rf $(BIN_DIR) $(TOOLS_DIR)
