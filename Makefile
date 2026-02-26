BINARY      = chipkey
BIN_DIR     = bin
BUNDLE_ID   = com.jeanregisser.chipkey
APP_BUNDLE  = $(BIN_DIR)/Chipkey.app
APP_MACOS   = $(APP_BUNDLE)/Contents/MacOS
APP_VERSION = 0.1.0

# Auto-detect signing identity and team ID from the keychain.
# Prefers "Developer ID Application"; falls back to "Apple Development".
SIGN_IDENTITY ?= $(shell security find-identity -v -p codesigning | \
	awk -F'"' '/Developer ID Application/ {found=$$2} !found && /Apple Development/ {found=$$2} END {print found}' 2>/dev/null)

TEAM_ID ?= $(shell echo "$(SIGN_IDENTITY)" | sed -n 's/.*(\([A-Z0-9]*\))$$/\1/p')

# Path to the provisioning profile (download from developer.apple.com).
PROVISIONING_PROFILE ?= chipkey.provisionprofile

.PHONY: build build-darwin build-linux bundle sign test clean

build: build-darwin

## Build a universal macOS binary (arm64 + x86_64). Must run on macOS.
build-darwin:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o $(BIN_DIR)/$(BINARY)-darwin-arm64 .
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY)-darwin-amd64 .
	lipo -create \
		-output $(BIN_DIR)/$(BINARY)-darwin \
		$(BIN_DIR)/$(BINARY)-darwin-arm64 \
		$(BIN_DIR)/$(BINARY)-darwin-amd64
	rm $(BIN_DIR)/$(BINARY)-darwin-arm64 $(BIN_DIR)/$(BINARY)-darwin-amd64

## Build Linux binaries (can cross-compile from macOS).
build-linux:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/$(BINARY)-linux-arm64 .

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

test:
	go test -v ./...

clean:
	rm -rf $(BIN_DIR)
