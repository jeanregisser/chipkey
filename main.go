package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/facebookincubator/sks"
)

// Set at build time via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// --- JSON output ---

type result map[string]any

func respond(r result) {
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, `{"ok":false,"error":{"code":"JSON_ERROR","message":%q}}`+"\n", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func fail(code, message string) {
	_ = json.NewEncoder(os.Stdout).Encode(result{
		"ok":    false,
		"error": map[string]string{"code": code, "message": message},
	})
	os.Exit(1)
}

// --- Helpers ---

// splitKeyID parses a "label:tag" key identity string.
// Both label and tag must be non-empty. The tag may itself contain colons.
func splitKeyID(keyID string) (label, tag string, err error) {
	parts := strings.SplitN(keyID, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("key-id %q is not valid — must be non-empty label:tag (e.g. chipkey:my-uuid)", keyID)
	}
	return parts[0], parts[1], nil
}

func parseKeyID(keyID string) (label, tag string) {
	label, tag, err := splitKeyID(keyID)
	if err != nil {
		fail("INVALID_KEY_ID", err.Error())
	}
	return label, tag
}

func pubkeyHex(pub *ecdsa.PublicKey) string {
	// Uncompressed P-256 point: 04 || X || Y (65 bytes)
	b := make([]byte, 65)
	b[0] = 0x04
	pub.X.FillBytes(b[1:33])
	pub.Y.FillBytes(b[33:65])
	return "0x" + hex.EncodeToString(b)
}

// ecdsaDERSig is the ASN.1 structure of a DER-encoded ECDSA signature.
type ecdsaDERSig struct {
	R, S *big.Int
}

// derToRawRS converts a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
// to the raw 64-byte R||S format expected by Ethereum and similar consumers.
func derToRawRS(der []byte) ([]byte, error) {
	var sig ecdsaDERSig
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("invalid DER signature: %w", err)
	}
	if sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, fmt.Errorf("signature values exceed P-256 field size")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

// --- Commands ---

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	keyID := fs.String("key-id", "", "key identity in label:tag format")
	if err := fs.Parse(args); err != nil {
		fail("INVALID_ARGUMENTS", err.Error())
	}
	if *keyID == "" {
		fail("INVALID_ARGUMENTS", "--key-id is required")
	}

	label, tag := parseKeyID(*keyID)

	// sks.NewKey returns an existing key if label:tag already exists,
	// or creates a new one. useBiometrics=false, accessibleWhenUnlockedOnly=true.
	key, err := sks.NewKey(label, tag, false, true, nil)
	if err != nil {
		fail("KEY_CREATION_FAILED", err.Error())
	}
	defer key.Close()

	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub == nil || pub.X == nil {
		fail("PUBLIC_KEY_UNAVAILABLE", "failed to retrieve public key after creation")
	}

	respond(result{
		"ok":        true,
		"publicKey": pubkeyHex(pub),
		"keyId":     *keyID,
	})
}

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyID := fs.String("key-id", "", "key identity in label:tag format")
	payloadHex := fs.String("payload-hex", "", "hex-encoded payload to sign")
	hashMode := fs.String("hash", "sha256", "hash mode: sha256 (default) or none (payload must be a 32-byte digest)")
	if err := fs.Parse(args); err != nil {
		fail("INVALID_ARGUMENTS", err.Error())
	}
	if *keyID == "" {
		fail("INVALID_ARGUMENTS", "--key-id is required")
	}
	if *payloadHex == "" {
		fail("INVALID_ARGUMENTS", "--payload-hex is required")
	}

	label, tag := parseKeyID(*keyID)

	raw := strings.TrimPrefix(strings.TrimPrefix(*payloadHex, "0x"), "0X")
	payload, err := hex.DecodeString(raw)
	if err != nil {
		fail("INVALID_PAYLOAD", "payload-hex is not valid hex")
	}

	var digest []byte
	switch *hashMode {
	case "sha256":
		h := sha256.Sum256(payload)
		digest = h[:]
	case "none":
		if len(payload) != 32 {
			fail("INVALID_DIGEST_LENGTH", "--hash none requires payload to be exactly 32 bytes")
		}
		digest = payload
	default:
		fail("INVALID_HASH_MODE", fmt.Sprintf("unsupported hash mode %q — use sha256 or none", *hashMode))
	}

	// FromLabelTag constructs a key reference without a keychain lookup.
	// Sign will look up the key by label:tag at signing time.
	key := sks.FromLabelTag(label + ":" + tag)
	der, err := key.Sign(nil, digest, nil)
	if err != nil {
		fail("SIGNING_FAILED", err.Error())
	}

	rawSig, err := derToRawRS(der)
	if err != nil {
		fail("SIGNATURE_PARSE_FAILED", err.Error())
	}

	respond(result{
		"ok":        true,
		"signature": "0x" + hex.EncodeToString(rawSig),
	})
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	keyID := fs.String("key-id", "", "key identity in label:tag format")
	if err := fs.Parse(args); err != nil {
		fail("INVALID_ARGUMENTS", err.Error())
	}
	if *keyID == "" {
		fail("INVALID_ARGUMENTS", "--key-id is required")
	}

	label, tag := parseKeyID(*keyID)

	key, err := sks.LoadKey(label, tag, nil)
	exists := err == nil && key != nil
	if exists {
		key.Close()
	}

	respond(result{
		"ok":     true,
		"exists": exists,
		"curve":  "p256",
	})
}

func main() {
	if len(os.Args) < 2 {
		fail("INVALID_ARGUMENTS", "usage: chipkey <create|sign|info|version> [flags]")
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "create":
		cmdCreate(args)
	case "sign":
		cmdSign(args)
	case "info":
		cmdInfo(args)
	case "version":
		respond(result{
			"ok":      true,
			"version": version,
			"commit":  commit,
			"date":    date,
		})
	default:
		fail("INVALID_COMMAND", fmt.Sprintf("unknown command %q — use create, sign, info, or version", cmd))
	}
}
