package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testBinary is the path to the compiled binary used by CLI integration tests.
var testBinary = "./chipkey-test"

func init() {
	if runtime.GOOS == "windows" {
		testBinary += ".exe"
	}
}

// TestMain builds the binary once before running CLI integration tests.
func TestMain(m *testing.M) {
	cmd := exec.Command("go", "build", "-o", testBinary, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("failed to build test binary: " + err.Error())
	}
	code := m.Run()
	os.Remove(testBinary)
	os.Exit(code)
}

// runChipkey executes the test binary and returns the parsed JSON response and exit code.
func runChipkey(args ...string) (map[string]any, int) {
	cmd := exec.Command(testBinary, args...)
	out, _ := cmd.Output() // Output() captures stdout; error is from non-zero exit
	if len(out) == 0 {
		return nil, cmd.ProcessState.ExitCode()
	}
	var result map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		panic("binary returned non-JSON: " + string(out))
	}
	return result, cmd.ProcessState.ExitCode()
}

func errorCode(result map[string]any) string {
	errField, ok := result["error"].(map[string]any)
	if !ok {
		return ""
	}
	code, _ := errField["code"].(string)
	return code
}

// --- Unit tests: splitKeyID ---

func TestSplitKeyID_Valid(t *testing.T) {
	cases := []struct {
		input     string
		wantLabel string
		wantTag   string
	}{
		{"chipkey:abc-uuid", "chipkey", "abc-uuid"},
		{"agent-wallet:550e8400-e29b-41d4-a716-446655440000", "agent-wallet", "550e8400-e29b-41d4-a716-446655440000"},
		// tag may contain colons
		{"label:tag:with:colons", "label", "tag:with:colons"},
	}
	for _, c := range cases {
		label, tag, err := splitKeyID(c.input)
		if err != nil {
			t.Errorf("splitKeyID(%q) unexpected error: %v", c.input, err)
			continue
		}
		if label != c.wantLabel {
			t.Errorf("splitKeyID(%q) label = %q, want %q", c.input, label, c.wantLabel)
		}
		if tag != c.wantTag {
			t.Errorf("splitKeyID(%q) tag = %q, want %q", c.input, tag, c.wantTag)
		}
	}
}

func TestSplitKeyID_Invalid(t *testing.T) {
	cases := []string{
		"",        // empty
		"nocolon", // no separator
		"label:",  // empty tag
		":tag",    // empty label
		":",       // both empty
	}
	for _, input := range cases {
		_, _, err := splitKeyID(input)
		if err == nil {
			t.Errorf("splitKeyID(%q) expected error, got nil", input)
		}
	}
}

// --- Unit tests: derToRawRS ---

// encodeDER builds a minimal DER ECDSA signature from two big.Ints.
func encodeDER(r, s *big.Int) []byte {
	encodeInt := func(n *big.Int) []byte {
		b := n.Bytes()
		if len(b) == 0 {
			b = []byte{0}
		}
		// DER requires a leading 0x00 if the high bit is set
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	rb := encodeInt(r)
	sb := encodeInt(s)
	inner := append(rb, sb...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

func TestDerToRawRS(t *testing.T) {
	cases := []struct {
		name string
		r    *big.Int
		s    *big.Int
	}{
		{
			name: "small values padded to 32 bytes",
			r:    big.NewInt(1),
			s:    big.NewInt(2),
		},
		{
			// High bit set on both — DER adds a leading 0x00 to each integer.
			name: "high-bit r and s",
			r:    new(big.Int).SetBytes(mustDecodeHex("8000000000000000000000000000000000000000000000000000000000000001")),
			s:    new(big.Int).SetBytes(mustDecodeHex("ff00000000000000000000000000000000000000000000000000000000000002")),
		},
		{
			name: "max 32-byte values",
			r:    new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
			s:    new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(2)),
		},
		{
			name: "real-world P-256 shape",
			r:    new(big.Int).SetBytes(mustDecodeHex("d2aa79b50018f5d1c42e1ec80e21218c8d61573f2ce34c5b65d7703dd0eb571e")),
			s:    new(big.Int).SetBytes(mustDecodeHex("a1b2c3d4e5f607080910111213141516171819202122232425262728292a2b2c")),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			der := encodeDER(c.r, c.s)
			raw, err := derToRawRS(der)
			if err != nil {
				t.Fatalf("derToRawRS error: %v", err)
			}
			if len(raw) != 64 {
				t.Fatalf("expected 64 bytes, got %d", len(raw))
			}
			gotR := new(big.Int).SetBytes(raw[:32])
			gotS := new(big.Int).SetBytes(raw[32:])
			if gotR.Cmp(c.r) != 0 {
				t.Errorf("r mismatch: got %x, want %x", gotR, c.r)
			}
			if gotS.Cmp(c.s) != 0 {
				t.Errorf("s mismatch: got %x, want %x", gotS, c.s)
			}
		})
	}
}

func TestDerToRawRS_Invalid(t *testing.T) {
	cases := []struct {
		name string
		der  []byte
	}{
		{"empty", []byte{}},
		{"wrong tag", []byte{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}},
		{"truncated", []byte{0x30, 0x06, 0x02, 0x01}},
		{"wrong integer tag", []byte{0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := derToRawRS(c.der)
			if err == nil {
				t.Errorf("expected error for %q, got nil", c.name)
			}
		})
	}
}

// --- CLI integration tests (argument validation, no SE/TPM access required) ---

func TestCLI_ArgumentErrors(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCode string
	}{
		{"no args", []string{}, "INVALID_ARGUMENTS"},
		{"unknown command", []string{"frobnicate"}, "INVALID_COMMAND"},
		{"create: missing key-id", []string{"create"}, "INVALID_ARGUMENTS"},
		{"create: key-id no colon", []string{"create", "--key-id", "nocolon"}, "INVALID_KEY_ID"},
		{"create: key-id empty label", []string{"create", "--key-id", ":tag"}, "INVALID_KEY_ID"},
		{"create: key-id empty tag", []string{"create", "--key-id", "label:"}, "INVALID_KEY_ID"},
		{"sign: missing key-id", []string{"sign", "--payload-hex", "0xdeadbeef"}, "INVALID_ARGUMENTS"},
		{"sign: missing payload", []string{"sign", "--key-id", "chipkey:abc"}, "INVALID_ARGUMENTS"},
		{"sign: invalid payload hex", []string{"sign", "--key-id", "chipkey:abc", "--payload-hex", "notvalid!"}, "INVALID_PAYLOAD"},
		{"sign: invalid hash mode", []string{"sign", "--key-id", "chipkey:abc", "--payload-hex", "0xab", "--hash", "md5"}, "INVALID_HASH_MODE"},
		{"sign: hash none wrong len", []string{"sign", "--key-id", "chipkey:abc", "--payload-hex", "0xdeadbeef", "--hash", "none"}, "INVALID_DIGEST_LENGTH"},
		{"info: missing key-id", []string{"info"}, "INVALID_ARGUMENTS"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, code := runChipkey(c.args...)
			if code == 0 {
				t.Fatalf("expected non-zero exit code, got 0 with result: %v", result)
			}
			if ec := errorCode(result); ec != c.wantCode {
				t.Errorf("error code = %q, want %q", ec, c.wantCode)
			}
		})
	}
}

func TestCLI_Sign_PayloadHexPrefixes(t *testing.T) {
	// 0x, 0X, and no-prefix should all parse successfully (failure is at signing, not parsing).
	for _, prefix := range []string{"0x", "0X", ""} {
		result, _ := runChipkey("sign", "--key-id", "chipkey:abc", "--payload-hex", prefix+"deadbeef")
		if ec := errorCode(result); ec == "INVALID_PAYLOAD" {
			t.Errorf("prefix %q: got INVALID_PAYLOAD, want any other error", prefix)
		}
	}
}

// --- E2E tests (require a code-signed binary with SE entitlements) ---

// TestE2E_CreateSignInfo exercises the full create → info → sign flow against
// the real hardware backend. On an unsigned binary the test is skipped
// automatically; run it after `make sign` by pointing CHIPKEY_BINARY at the
// signed binary:
//
//	CHIPKEY_BINARY=bin/chipkey-darwin go test -run TestE2E ./...
func TestE2E_CreateSignInfo(t *testing.T) {
	binary := os.Getenv("CHIPKEY_BINARY")
	if binary == "" {
		binary = testBinary
	}

	run := func(args ...string) (map[string]any, int) {
		cmd := exec.Command(binary, args...)
		out, _ := cmd.Output()
		if len(out) == 0 {
			return nil, cmd.ProcessState.ExitCode()
		}
		var result map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
			t.Fatalf("binary returned non-JSON: %s", out)
		}
		return result, cmd.ProcessState.ExitCode()
	}

	skipIfHardwareUnavailable := func(t *testing.T, result map[string]any, code int, op string) {
		t.Helper()
		if code == 0 {
			return
		}
		ec := errorCode(result)
		// These codes indicate missing entitlements or hardware not present.
		if ec == "KEY_CREATION_FAILED" || ec == "SIGNING_FAILED" || ec == "KEY_LOOKUP_FAILED" {
			t.Skipf("skipping e2e: hardware/entitlements unavailable during %q (%s) — sign the binary with `make sign` and set CHIPKEY_BINARY", op, ec)
		}
		t.Fatalf("%s failed (code %d): %v", op, code, result)
	}

	keyID := fmt.Sprintf("chipkey-e2e:%d", time.Now().UnixNano())

	// 1. Create a key.
	t.Logf("create --key-id %s", keyID)
	result, code := run("create", "--key-id", keyID)
	skipIfHardwareUnavailable(t, result, code, "create")

	publicKey, _ := result["publicKey"].(string)
	if !strings.HasPrefix(publicKey, "0x") || len(publicKey) != 132 {
		t.Fatalf("create: invalid publicKey %q (want 0x + 130 hex chars for 65-byte uncompressed P-256)", publicKey)
	}
	if result["keyId"] != keyID {
		t.Errorf("create: keyId = %v, want %q", result["keyId"], keyID)
	}
	t.Logf("publicKey: %s", publicKey)

	// 2. Info: key must exist with correct metadata.
	result, code = run("info", "--key-id", keyID)
	if code != 0 {
		t.Fatalf("info failed: %v", result)
	}
	if result["exists"] != true {
		t.Errorf("info: exists = %v, want true", result["exists"])
	}
	if result["curve"] != "p256" {
		t.Errorf("info: curve = %v, want p256", result["curve"])
	}

	// Parse the public key for signature verification below.
	pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(publicKey, "0x"))
	if err != nil || len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		t.Fatalf("create: cannot decode publicKey for verification: %v", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
	pub.X = new(big.Int).SetBytes(pubKeyBytes[1:33])
	pub.Y = new(big.Int).SetBytes(pubKeyBytes[33:65])

	verifySig := func(t *testing.T, sigHex string, digest []byte) {
		t.Helper()
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if err != nil || len(sigBytes) != 64 {
			t.Fatalf("cannot decode signature %q: %v", sigHex, err)
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(pub, digest, r, s) {
			t.Errorf("signature verification failed")
		}
	}

	// 3. Sign with --hash sha256 (default): arbitrary payload, hashed internally.
	payload := mustDecodeHex("deadbeefcafe1234")
	result, code = run("sign", "--key-id", keyID, "--payload-hex", "0xdeadbeefcafe1234")
	if code != 0 {
		t.Fatalf("sign (sha256) failed: %v", result)
	}
	sig, _ := result["signature"].(string)
	if !strings.HasPrefix(sig, "0x") || len(sig) != 130 {
		t.Fatalf("sign: invalid signature %q (want 0x + 128 hex chars for 64-byte R||S)", sig)
	}
	digest256 := sha256sum(payload)
	verifySig(t, sig, digest256)
	t.Logf("signature (sha256): %s ✓", sig)

	// 4. Sign with --hash none: pass a pre-hashed 32-byte digest directly.
	rawDigest := mustDecodeHex(strings.Repeat("ab", 32))
	result, code = run("sign", "--key-id", keyID, "--payload-hex", "0x"+strings.Repeat("ab", 32), "--hash", "none")
	if code != 0 {
		t.Fatalf("sign (none) failed: %v", result)
	}
	sig, _ = result["signature"].(string)
	if !strings.HasPrefix(sig, "0x") || len(sig) != 130 {
		t.Fatalf("sign --hash none: invalid signature %q", sig)
	}
	verifySig(t, sig, rawDigest)
	t.Logf("signature (none): %s ✓", sig)
}

// --- Helpers ---

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("mustDecodeHex(%q): %v", s, err))
	}
	return b
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
