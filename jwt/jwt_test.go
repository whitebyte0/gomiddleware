package jwt

import (
	"testing"
	"time"
)

const testSecret = "this-is-a-test-secret-that-is-at-least-32-bytes-long"

func testJWTManager() *JWTManager {
	return NewJWTManager(JWTConfig{
		Secret:   testSecret,
		Issuer:   "test-issuer",
		Audience: "test-audience",
	})
}

func TestJWT_GenerateAndValidate(t *testing.T) {
	m := testJWTManager()

	token, err := m.Generate(GenerateInput{
		UserID: 42,
		Email:  "user@test.com",
		Role:   "admin",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	claims, err := m.Validate(token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID: got %d, want 42", claims.UserID)
	}
	if claims.Email != "user@test.com" {
		t.Errorf("Email: got %s, want user@test.com", claims.Email)
	}
	if claims.Role != "admin" {
		t.Errorf("Role: got %s, want admin", claims.Role)
	}
}

func TestJWT_SessionTokenInClaims(t *testing.T) {
	m := testJWTManager()

	token, _ := m.Generate(GenerateInput{
		UserID:       1,
		Email:        "a@b.com",
		SessionToken: "sess-uuid-1234",
	})

	claims, err := m.Validate(token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if claims.SessionToken != "sess-uuid-1234" {
		t.Errorf("SessionToken: got %q, want sess-uuid-1234", claims.SessionToken)
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	m := NewJWTManager(JWTConfig{
		Secret:     testSecret,
		Issuer:     "test",
		Audience:   "test",
		Expiration: 1 * time.Millisecond,
	})

	token, _ := m.Generate(GenerateInput{UserID: 1, Email: "a@b.com"})
	time.Sleep(10 * time.Millisecond)

	_, err := m.Validate(token)
	if err != ErrExpiredToken {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	m1 := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test"})
	m2 := NewJWTManager(JWTConfig{Secret: "another-secret-that-is-also-at-least-32-bytes-long!!", Issuer: "test", Audience: "test"})

	token, _ := m1.Generate(GenerateInput{UserID: 1, Email: "a@b.com"})
	_, err := m2.Validate(token)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestJWT_WrongIssuer(t *testing.T) {
	m1 := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "issuer-a", Audience: "test"})
	m2 := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "issuer-b", Audience: "test"})

	token, _ := m1.Generate(GenerateInput{UserID: 1, Email: "a@b.com"})
	_, err := m2.Validate(token)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestJWT_PanicsOnWeakSecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on weak secret")
		}
	}()
	NewJWTManager(JWTConfig{Secret: "short", Issuer: "test", Audience: "test"})
}

// --- Token Version ---

type mockVersionProvider struct{ version int64 }

func (m *mockVersionProvider) GetTokenVersion(userID int64) (int64, error) {
	return m.version, nil
}

func TestJWT_TokenVersionOutdated(t *testing.T) {
	vp := &mockVersionProvider{version: 1}
	m := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test", TokenVersionProvider: vp})

	token, _ := m.Generate(GenerateInput{UserID: 1, Email: "a@b.com", TokenVersion: 0})
	_, err := m.Validate(token)
	if err != ErrTokenVersionOutdated {
		t.Errorf("expected ErrTokenVersionOutdated, got %v", err)
	}
}

func TestJWT_TokenVersionCurrent(t *testing.T) {
	vp := &mockVersionProvider{version: 5}
	m := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test", TokenVersionProvider: vp})

	token, _ := m.Generate(GenerateInput{UserID: 1, Email: "a@b.com", TokenVersion: 5})
	_, err := m.Validate(token)
	if err != nil {
		t.Errorf("expected valid token, got %v", err)
	}
}

// --- Revocation ---

type mockRevokedStore struct{ revoked map[string]bool }

func newMockRevokedStore() *mockRevokedStore {
	return &mockRevokedStore{revoked: make(map[string]bool)}
}

func (s *mockRevokedStore) IsRevoked(hash string) (bool, error)                              { return s.revoked[hash], nil }
func (s *mockRevokedStore) Revoke(hash string, userID int64, expiresAt time.Time, reason string) error { s.revoked[hash] = true; return nil }

func TestJWT_RevokeAndValidate(t *testing.T) {
	store := newMockRevokedStore()
	m := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test", RevokedTokenStore: store})

	token, _ := m.Generate(GenerateInput{UserID: 1, Email: "a@b.com"})

	_, err := m.Validate(token)
	if err != nil {
		t.Fatalf("expected valid before revoke, got %v", err)
	}

	m.Revoke(token, 1, "logout")

	_, err = m.Validate(token)
	if err != ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

// --- Refresh ---

func TestJWT_Refresh(t *testing.T) {
	shortM := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test", Expiration: 1 * time.Millisecond, RefreshWindow: 1 * time.Hour})

	token, _ := shortM.Generate(GenerateInput{UserID: 1, Email: "a@b.com", Role: "admin"})
	time.Sleep(10 * time.Millisecond)

	m := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test", RefreshWindow: 1 * time.Hour})

	newToken, err := m.Refresh(token)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if newToken == token {
		t.Error("expected different token after refresh")
	}

	claims, err := m.Validate(newToken)
	if err != nil {
		t.Fatalf("refreshed token invalid: %v", err)
	}
	if claims.UserID != 1 {
		t.Errorf("UserID: got %d, want 1", claims.UserID)
	}
}

func TestJWT_RefreshNotExpired(t *testing.T) {
	m := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test"})
	token, _ := m.Generate(GenerateInput{UserID: 1, Email: "a@b.com"})

	_, err := m.Refresh(token)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for non-expired refresh, got %v", err)
	}
}

func TestJWT_RefreshWindowExpired(t *testing.T) {
	m := NewJWTManager(JWTConfig{Secret: testSecret, Issuer: "test", Audience: "test", Expiration: 1 * time.Millisecond, RefreshWindow: 1 * time.Millisecond})

	token, _ := m.Generate(GenerateInput{UserID: 1, Email: "a@b.com"})
	time.Sleep(20 * time.Millisecond)

	_, err := m.Refresh(token)
	if err != ErrRefreshWindowExpired {
		t.Errorf("expected ErrRefreshWindowExpired, got %v", err)
	}
}
