package jwt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenVersionProvider checks the current token version for a user.
// Used for logout-all: increment the version to invalidate all existing tokens.
// Return 0 if not using token versioning.
type TokenVersionProvider interface {
	GetTokenVersion(userID int64) (int64, error)
}

// RevokedTokenStore checks and stores revoked tokens.
// Implement with your database, Redis, etc.
type RevokedTokenStore interface {
	IsRevoked(tokenHash string) (bool, error)
	Revoke(tokenHash string, userID int64, expiresAt time.Time, reason string) error
}

// Claims represents JWT claims with optional app-specific metadata.
// Use the Metadata field to carry arbitrary key-value pairs (e.g. org_id,
// is_system_owner) without modifying the library.
type Claims struct {
	UserID       int64                  `json:"user_id"`
	Email        string                 `json:"email"`
	Role         string                 `json:"role"`
	SessionToken string                 `json:"session_token,omitempty"`
	TokenVersion int64                  `json:"token_version,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	jwt.RegisteredClaims
}

// JWTConfig configures the JWT manager.
type JWTConfig struct {
	Secret               string        // Required: signing secret (min 32 bytes)
	Issuer               string        // Required: token issuer
	Audience             string        // Required: token audience
	Expiration           time.Duration // Default: 1 hour
	RefreshWindow        time.Duration // Default: 24 hours (how long after expiry a token can be refreshed)
	TokenVersionProvider TokenVersionProvider // Optional: for logout-all support
	RevokedTokenStore    RevokedTokenStore    // Optional: for token revocation
}

// JWTManager handles JWT generation, validation, refresh, and revocation.
type JWTManager struct {
	secret        []byte
	issuer        string
	audience      string
	expiration    time.Duration
	refreshWindow time.Duration
	versionProv   TokenVersionProvider
	revokedStore  RevokedTokenStore
}

// NewJWTManager creates a new JWT manager.
// Panics if secret is less than 32 bytes or issuer/audience are empty.
func NewJWTManager(cfg JWTConfig) *JWTManager {
	if len(cfg.Secret) < 32 {
		panic(ErrWeakSecret)
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		panic("gomiddleware: jwt issuer and audience are required")
	}
	if cfg.Expiration == 0 {
		cfg.Expiration = time.Hour
	}
	if cfg.RefreshWindow == 0 {
		cfg.RefreshWindow = 24 * time.Hour
	}

	return &JWTManager{
		secret:        []byte(cfg.Secret),
		issuer:        cfg.Issuer,
		audience:      cfg.Audience,
		expiration:    cfg.Expiration,
		refreshWindow: cfg.RefreshWindow,
		versionProv:   cfg.TokenVersionProvider,
		revokedStore:  cfg.RevokedTokenStore,
	}
}

// GenerateInput holds the fields for generating a JWT token.
// Only UserID is required. All other fields are optional.
type GenerateInput struct {
	UserID       int64
	Email        string
	Role         string
	SessionToken string
	TokenVersion int64
	Metadata     map[string]interface{} // App-specific key-value pairs
}

// Generate creates a new signed JWT token.
func (m *JWTManager) Generate(input GenerateInput) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID:       input.UserID,
		Email:        input.Email,
		Role:         input.Role,
		SessionToken: input.SessionToken,
		TokenVersion: input.TokenVersion,
		Metadata:     input.Metadata,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// Validate parses and validates a JWT token. Returns claims if valid.
// Checks: signature, expiration, issuer, audience, token version, revocation.
func (m *JWTManager) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, m.keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if err := m.validateClaims(claims); err != nil {
		return nil, err
	}

	if err := m.checkVersion(claims); err != nil {
		return nil, err
	}

	if err := m.checkRevoked(tokenString); err != nil {
		return nil, err
	}

	return claims, nil
}

// Refresh generates a new token from an expired token within the refresh window.
// The old token must be expired (strict policy) and within the refresh window.
func (m *JWTManager) Refresh(oldToken string) (string, error) {
	// Parse without expiration validation
	token, err := jwt.ParseWithClaims(oldToken, &Claims{}, m.keyFunc, jwt.WithoutClaimsValidation())
	if err != nil {
		return "", ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", ErrInvalidToken
	}

	if err := m.validateClaims(claims); err != nil {
		return "", err
	}

	// Must be expired (strict refresh policy)
	if claims.ExpiresAt == nil || time.Now().Before(claims.ExpiresAt.Time) {
		return "", ErrInvalidToken
	}

	// Must be within refresh window
	if time.Since(claims.ExpiresAt.Time) > m.refreshWindow {
		return "", ErrRefreshWindowExpired
	}

	if err := m.checkVersion(claims); err != nil {
		return "", err
	}

	if err := m.checkRevoked(oldToken); err != nil {
		return "", err
	}

	// Get current version for the new token
	var currentVersion int64
	if m.versionProv != nil {
		currentVersion, _ = m.versionProv.GetTokenVersion(claims.UserID)
	}

	return m.Generate(GenerateInput{
		UserID:       claims.UserID,
		Email:        claims.Email,
		Role:         claims.Role,
		SessionToken: claims.SessionToken,
		TokenVersion: currentVersion,
		Metadata:     claims.Metadata,
	})
}

// Revoke adds a token to the revocation list.
// Requires RevokedTokenStore to be configured.
func (m *JWTManager) Revoke(tokenString string, userID int64, reason string) error {
	if m.revokedStore == nil {
		return nil
	}

	// Try to get expiration from token
	expiresAt := time.Now().Add(m.expiration)
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, m.keyFunc, jwt.WithoutClaimsValidation())
	if err == nil {
		if claims, ok := token.Claims.(*Claims); ok && claims.ExpiresAt != nil {
			expiresAt = claims.ExpiresAt.Time
		}
	}

	return m.revokedStore.Revoke(hashToken(tokenString), userID, expiresAt, reason)
}

// --- internal helpers ---

func (m *JWTManager) keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, ErrInvalidSigningMethod
	}
	return m.secret, nil
}

func (m *JWTManager) validateClaims(claims *Claims) error {
	if claims.Issuer != m.issuer {
		return ErrInvalidToken
	}
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == m.audience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return ErrInvalidToken
	}
	return nil
}

func (m *JWTManager) checkVersion(claims *Claims) error {
	if m.versionProv == nil {
		return nil
	}
	currentVersion, err := m.versionProv.GetTokenVersion(claims.UserID)
	if err != nil {
		return ErrTokenVersionOutdated
	}
	if claims.TokenVersion < currentVersion {
		return ErrTokenVersionOutdated
	}
	return nil
}

func (m *JWTManager) checkRevoked(tokenString string) error {
	if m.revokedStore == nil {
		return nil
	}
	revoked, err := m.revokedStore.IsRevoked(hashToken(tokenString))
	if err != nil {
		return ErrTokenRevoked
	}
	if revoked {
		return ErrTokenRevoked
	}
	return nil
}

func hashToken(tokenString string) string {
	h := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(h[:])
}
