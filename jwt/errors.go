package jwt

import "errors"

var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrExpiredToken         = errors.New("token has expired")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrTokenRevoked         = errors.New("token has been revoked")
	ErrTokenVersionOutdated = errors.New("token version outdated")
	ErrRefreshWindowExpired = errors.New("refresh window has expired")
	ErrWeakSecret           = errors.New("secret must be at least 32 bytes")
)
