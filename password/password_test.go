package password

import (
	"strings"
	"testing"
)

// --- Bcrypt ---

func TestBcryptHasher_HashAndVerify(t *testing.T) {
	h := NewBcryptHasher()
	hash, err := h.Hash("mypassword")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	ok, err := h.Verify("mypassword", hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("expected password to match")
	}
}

func TestBcryptHasher_WrongPassword(t *testing.T) {
	h := NewBcryptHasher()
	hash, _ := h.Hash("correct")

	ok, err := h.Verify("wrong", hash)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("expected password to NOT match")
	}
}

func TestBcryptHasher_CustomCost(t *testing.T) {
	h := NewBcryptHasher(12)
	hash, err := h.Hash("test")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	ok, _ := h.Verify("test", hash)
	if !ok {
		t.Error("expected match with custom cost")
	}
}

func TestBcryptHasher_DifferentHashesForSamePassword(t *testing.T) {
	h := NewBcryptHasher()
	h1, _ := h.Hash("same")
	h2, _ := h.Hash("same")

	if h1 == h2 {
		t.Error("expected different hashes (different salt)")
	}
}

// --- Argon2id ---

func TestArgon2idHasher_HashAndVerify(t *testing.T) {
	h := NewArgon2idHasher()
	hash, err := h.Hash("mypassword")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected argon2id hash format, got %q", hash[:20])
	}

	ok, err := h.Verify("mypassword", hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("expected password to match")
	}
}

func TestArgon2idHasher_WrongPassword(t *testing.T) {
	h := NewArgon2idHasher()
	hash, _ := h.Hash("correct")

	ok, err := h.Verify("wrong", hash)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("expected password to NOT match")
	}
}

func TestArgon2idHasher_DifferentHashesForSamePassword(t *testing.T) {
	h := NewArgon2idHasher()
	h1, _ := h.Hash("same")
	h2, _ := h.Hash("same")

	if h1 == h2 {
		t.Error("expected different hashes (different salt)")
	}
}

// --- Interface compliance ---

func TestHasherInterface(t *testing.T) {
	// Both must satisfy the Hasher interface
	var _ Hasher = NewBcryptHasher()
	var _ Hasher = NewArgon2idHasher()
}
