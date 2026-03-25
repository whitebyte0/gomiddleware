package jwt

import (
	"time"

	"gorm.io/gorm"
)

// --- GORM Revoked Token Store ---

// RevokedToken is the GORM model for storing revoked JWT tokens.
type RevokedToken struct {
	ID        uint      `gorm:"primarykey"`
	TokenHash string    `gorm:"type:varchar(64);uniqueIndex;not null"`
	UserID    int64     `gorm:"not null;index"`
	ExpiresAt time.Time `gorm:"not null;index"`
	Reason    string    `gorm:"type:varchar(255)"`
	CreatedAt time.Time `gorm:"not null"`
}

// TableName returns the table name for the RevokedToken model.
func (RevokedToken) TableName() string {
	return "revoked_tokens"
}

// GORMRevokedTokenStore implements RevokedTokenStore using GORM.
type GORMRevokedTokenStore struct {
	db *gorm.DB
}

// NewGORMRevokedTokenStore creates a revoked token store backed by GORM.
func NewGORMRevokedTokenStore(db *gorm.DB) *GORMRevokedTokenStore {
	return &GORMRevokedTokenStore{db: db}
}

func (s *GORMRevokedTokenStore) IsRevoked(tokenHash string) (bool, error) {
	var count int64
	err := s.db.Model(&RevokedToken{}).
		Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).
		Count(&count).Error
	return count > 0, err
}

func (s *GORMRevokedTokenStore) Revoke(tokenHash string, userID int64, expiresAt time.Time, reason string) error {
	return s.db.Create(&RevokedToken{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Reason:    reason,
		CreatedAt: time.Now(),
	}).Error
}

// CleanupExpired removes revoked tokens that have passed their expiration.
// Call periodically to keep the table small.
func (s *GORMRevokedTokenStore) CleanupExpired() (int64, error) {
	result := s.db.Where("expires_at < ?", time.Now()).Delete(&RevokedToken{})
	return result.RowsAffected, result.Error
}

// --- GORM Token Version Provider ---

// tokenVersionUser is a minimal model for reading token_version from a users table.
type tokenVersionUser struct {
	ID           int64 `gorm:"primarykey"`
	TokenVersion int64
}

func (tokenVersionUser) TableName() string {
	return "users"
}

// GORMTokenVersionProvider implements TokenVersionProvider by reading
// the token_version column from the users table.
type GORMTokenVersionProvider struct {
	db *gorm.DB
}

// NewGORMTokenVersionProvider creates a token version provider backed by GORM.
// Assumes your users table has a `token_version` column (int64, default 0).
func NewGORMTokenVersionProvider(db *gorm.DB) *GORMTokenVersionProvider {
	return &GORMTokenVersionProvider{db: db}
}

func (p *GORMTokenVersionProvider) GetTokenVersion(userID int64) (int64, error) {
	var user tokenVersionUser
	err := p.db.Select("token_version").Where("id = ?", userID).First(&user).Error
	if err != nil {
		return 0, err
	}
	return user.TokenVersion, nil
}
