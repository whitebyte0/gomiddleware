package password

import (
	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

// Hasher is the interface for password hashing and verification.
// Implement this to use a custom algorithm, or use the provided
// NewBcryptHasher() and NewArgon2idHasher().
type Hasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) (bool, error)
}

// --- Bcrypt ---

type bcryptHasher struct {
	cost int
}

// NewBcryptHasher returns a Hasher using bcrypt.
// Cost controls work factor (default 12, recommended 12-14 for production).
func NewBcryptHasher(cost ...int) Hasher {
	c := 12
	if len(cost) > 0 && cost[0] > 0 {
		c = cost[0]
	}
	return &bcryptHasher{cost: c}
}

func (h *bcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (h *bcryptHasher) Verify(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --- Argon2id ---

type argon2idHasher struct {
	params *argon2id.Params
}

// NewArgon2idHasher returns a Hasher using Argon2id (recommended for new projects).
// Uses secure defaults: memory=64MB, iterations=3, parallelism=2, salt=16 bytes, key=32 bytes.
func NewArgon2idHasher() Hasher {
	return &argon2idHasher{
		params: &argon2id.Params{
			Memory:      64 * 1024, // 64 MB
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

func (h *argon2idHasher) Hash(password string) (string, error) {
	return argon2id.CreateHash(password, h.params)
}

func (h *argon2idHasher) Verify(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
