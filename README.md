# chipkey

Give any machine a hardware-bound signing identity. chipkey is a JSON CLI that creates and signs with **non-extractable ECDSA keys** stored in your device's security hardware -- Secure Enclave on Mac, TPM 2.0 on Linux and Windows.

Private keys never leave the chip. Not to disk, not to the cloud, not to you. If the device is lost or destroyed, the keys are gone. That's a feature: there is nothing to steal, leak, or subpoena.

## Use cases

- **AI agents with their own identity** -- Give an agent a hardware-bound key pair. It can sign actions, outputs, or transactions autonomously, but nobody -- not even the operator -- can extract the private key.
- **Device attestation** -- Prove a request came from a specific physical machine, not a cloned credential. The key is fused to the hardware and can't be copied.
- **Local-first crypto custody** -- No cloud KMS, no HSM service, no API keys to rotate. Any machine with security hardware becomes a non-custodial signer.
- **Artifact signing** -- Sign builds, releases, or documents with a key that's physically bound to your machine. Even a full disk compromise can't leak it.

## How it works

chipkey is a thin wrapper around [sks](https://github.com/facebookincubator/sks) (Secure Key Store), a Go library from Meta that abstracts Secure Enclave and TPM behind a unified API. chipkey adds a JSON CLI on top, making it callable from any language.

| Platform | Hardware | Notes |
|----------|----------|-------|
| macOS 11+ | Secure Enclave (Apple Silicon, T2) | Requires a signed `.app` bundle (see [macOS key scoping](#macos-key-scoping)) |
| Linux | TPM 2.0 | |
| Windows | TPM 2.0 | |

Keys are ECDSA P-256 (secp256r1). Signatures are returned in the 64-byte raw `R||S` format used by Ethereum and similar systems. Keys are non-exportable by design -- there is no backup or recovery mechanism, so plan for key rotation.

## Installation

### Download a release

Grab the latest archive for your platform from the [Releases](https://github.com/jeanregisser/chipkey/releases) page.

**macOS**: download `Chipkey_*_macos_app.zip`, unzip, and run the binary inside the bundle:

```sh
Chipkey.app/Contents/MacOS/chipkey version
```

**Linux / Windows**: download the appropriate archive and extract the `chipkey` binary.

### Build from source

```sh
git clone https://github.com/jeanregisser/chipkey.git
cd chipkey
make build    # universal macOS binary (requires macOS)
make bundle   # signed .app bundle (requires Developer ID certificate)
```

For Linux or Windows cross-compilation: `make build-linux` or `make build-windows`.

## Usage

All commands output JSON to stdout and use exit code 1 on failure.

### Create a key

```sh
chipkey create --key-id "myapp:some-uuid"
```

```json
{"keyId":"myapp:some-uuid","ok":true,"publicKey":"0x04..."}
```

The `--key-id` is a `label:tag` pair. If a key with that identity already exists, its public key is returned without creating a duplicate.

### Sign a payload

```sh
chipkey sign --key-id "myapp:some-uuid" --payload-hex "0xdeadbeef"
```

```json
{"ok":true,"signature":"0x..."}
```

By default, the payload is SHA-256 hashed before signing. To pass a pre-hashed 32-byte digest directly:

```sh
chipkey sign --key-id "myapp:some-uuid" --payload-hex "0x<64-hex-chars>" --hash none
```

### Check if a key exists

```sh
chipkey info --key-id "myapp:some-uuid"
```

```json
{"curve":"p256","exists":true,"ok":true}
```

### Version

```sh
chipkey version
```

```json
{"commit":"abc1234","date":"2026-02-26T10:30:00Z","ok":true,"version":"1.0.0"}
```

## macOS key scoping

On macOS, sks uses the Data Protection Keychain, which scopes key access by application identifier. The `com.apple.application-identifier` entitlement (`<TeamID>.<BundleID>`) in the signed `.app` bundle determines which keys a binary can see. A binary signed with a different team or bundle identifier cannot access keys created by another -- they live in separate keychain namespaces enforced by the OS.

The pre-built releases are signed with the project's Developer ID. If you build and sign from source with your own certificate, your keys will be in a separate namespace.

## Development

### Prerequisites

- Go 1.24+
- macOS for Secure Enclave builds (CGO required for the sks darwin backend)
- An Apple Developer ID Application certificate (for signing the `.app` bundle)

### Make targets

| Target | Description |
|--------|-------------|
| `make build` | Build universal macOS binary |
| `make build-linux` | Cross-compile Linux amd64/arm64 |
| `make build-windows` | Cross-compile Windows amd64/arm64 |
| `make bundle` | Build, sign, and package the `.app` bundle |
| `make test` | Run tests |
| `make lint` | Run golangci-lint (installs it first if needed) |
| `make check-tidy` | Verify `go.mod`/`go.sum` are tidy |
| `make tools` | Install dev tools into `.tools/` |
| `make clean` | Remove build artifacts and tools |

### Running tests

```sh
make test
```

Unit and CLI argument-validation tests run on any platform. The end-to-end test (`TestE2E_CreateSignInfo`) requires a signed binary with Secure Enclave entitlements:

```sh
make bundle
CHIPKEY_BINARY=bin/Chipkey.app/Contents/MacOS/chipkey go test -run TestE2E ./...
```

### CI/CD

Pushes to `main` trigger the full pipeline:

1. **Lint** -- golangci-lint, `go mod tidy` check, goreleaser config validation
2. **Test** -- `go test` on macOS, Linux, and Windows
3. **Version** -- Semantic version determined from [Conventional Commits](https://www.conventionalcommits.org/)
4. **Release** -- goreleaser builds Linux/Windows archives, then the signed macOS `.app` bundle is built and uploaded

To enable macOS code signing in CI, add these repository secrets:

| Secret | Description |
|--------|-------------|
| `APPLE_CERTIFICATE_P12_BASE64` | Base64-encoded `.p12` export of your Developer ID Application certificate |
| `APPLE_CERTIFICATE_PASSWORD` | Password used when exporting the `.p12` |

The CI checks the certificate's expiry and warns when it's within 30 days of expiring.

## Error codes

All errors include a machine-readable code and a human-readable message:

```json
{"error":{"code":"INVALID_KEY_ID","message":"key-id \"bad\" is not valid — must be non-empty label:tag (e.g. chipkey:my-uuid)"},"ok":false}
```

| Code | Meaning |
|------|---------|
| `INVALID_ARGUMENTS` | Missing or malformed flags |
| `INVALID_COMMAND` | Unknown subcommand |
| `INVALID_KEY_ID` | `--key-id` is not in `label:tag` format |
| `INVALID_PAYLOAD` | `--payload-hex` is not valid hex |
| `INVALID_HASH_MODE` | `--hash` must be `sha256` or `none` |
| `INVALID_DIGEST_LENGTH` | `--hash none` requires exactly 32 bytes |
| `KEY_CREATION_FAILED` | Hardware key creation failed |
| `SIGNING_FAILED` | Signing operation failed |
| `PUBLIC_KEY_UNAVAILABLE` | Could not retrieve public key after creation |
| `SIGNATURE_PARSE_FAILED` | Internal error parsing DER signature |

## Acknowledgments

All the heavy lifting is done by [sks](https://github.com/facebookincubator/sks) from Meta. chipkey just adds a JSON CLI on top.

## License

[MIT](LICENSE)
