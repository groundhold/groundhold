package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeygenMintsAndRefusesOverwrite pins the crypto-root contract: keygen writes a
// valid 32-byte ed25519 seed at 0600, and REFUSES to overwrite an existing signing
// identity, leaving it byte-for-byte untouched. The refusal is atomic (O_EXCL): the
// signing key is the root of every signature's trust, so "create a NEW file, never
// overwrite" is the kernel's guarantee, not a Stat-then-write check with a TOCTOU
// window a concurrent create could slip a truncate into.
func TestKeygenMintsAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sign.key")

	if code := runKeygen(path); code != 0 {
		t.Fatalf("keygen must succeed on a fresh path, got exit %d", code)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("seed file perms = %o, want 0600 (a signing seed is owner-only)", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("seed is not a hex-encoded 32-byte ed25519 seed: len=%d err=%v", len(seed), err)
	}

	// A second keygen on the same path must REFUSE, and leave the existing identity
	// byte-for-byte intact — never truncate or overwrite a signing key.
	if code := runKeygen(path); code == 0 {
		t.Fatal("keygen must REFUSE an existing signing identity, not overwrite it")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatal("a refused keygen must leave the existing key byte-for-byte untouched")
	}
}
