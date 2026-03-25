package session

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrSessionExpired = errors.New("session has expired")

// Session represents an active user session stored in the database.
type Session struct {
	ID             uint      `gorm:"primarykey" json:"id"`
	SessionToken   string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"session_token"`
	UserID         int64     `gorm:"not null;index" json:"user_id"`
	CreatedAt      time.Time `gorm:"not null" json:"created_at"`
	LastActivityAt time.Time `gorm:"not null" json:"last_activity_at"`
	ExpiresAt      time.Time `gorm:"not null;index" json:"expires_at"`
	IPAddress      string    `gorm:"type:varchar(45)" json:"ip_address,omitempty"`
	UserAgent      string    `gorm:"type:text" json:"user_agent,omitempty"`
}

// TableName returns the table name for the Session model.
func (Session) TableName() string {
	return "sessions"
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionManager handles session CRUD operations via GORM.
type SessionManager struct {
	db         *gorm.DB
	expiration time.Duration
}

// NewSessionManager creates a new session manager.
// expiration: how long a session lives (e.g. 24 * time.Hour).
func NewSessionManager(db *gorm.DB, expiration time.Duration) *SessionManager {
	if expiration == 0 {
		expiration = 24 * time.Hour
	}
	return &SessionManager{db: db, expiration: expiration}
}

// Create creates a new session for a user. Returns the session with a generated token.
func (m *SessionManager) Create(userID int64, ipAddress, userAgent string) (*Session, error) {
	now := time.Now()
	session := &Session{
		SessionToken:   uuid.New().String(),
		UserID:         userID,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(m.expiration),
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
	}

	if err := m.db.Create(session).Error; err != nil {
		return nil, err
	}
	return session, nil
}

// Validate checks if a session token is valid (exists and not expired).
func (m *SessionManager) Validate(sessionToken string) (*Session, error) {
	var session Session
	err := m.db.Where("session_token = ?", sessionToken).First(&session).Error
	if err != nil {
		return nil, err
	}
	if session.IsExpired() {
		return nil, ErrSessionExpired
	}
	return &session, nil
}

// UpdateActivity updates the last activity timestamp (sliding window).
func (m *SessionManager) UpdateActivity(sessionToken string) error {
	return m.db.Model(&Session{}).
		Where("session_token = ?", sessionToken).
		Update("last_activity_at", time.Now()).Error
}

// Delete removes a specific session by token.
func (m *SessionManager) Delete(sessionToken string) error {
	return m.db.Where("session_token = ?", sessionToken).Delete(&Session{}).Error
}

// DeleteAll removes all sessions for a user.
func (m *SessionManager) DeleteAll(userID int64) error {
	return m.db.Where("user_id = ?", userID).Delete(&Session{}).Error
}

// DeleteByID removes a specific session by ID, scoped to a user (ownership check).
func (m *SessionManager) DeleteByID(sessionID uint, userID int64) error {
	result := m.db.Where("id = ? AND user_id = ?", sessionID, userID).Delete(&Session{})
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return result.Error
}

// List returns all active (non-expired) sessions for a user.
func (m *SessionManager) List(userID int64) ([]Session, error) {
	var sessions []Session
	err := m.db.Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Order("last_activity_at DESC").
		Find(&sessions).Error
	return sessions, err
}

// CleanupExpired removes all expired sessions from the database.
// Call this periodically (e.g. every hour via a background goroutine).
func (m *SessionManager) CleanupExpired() (int64, error) {
	result := m.db.Where("expires_at < ?", time.Now()).Delete(&Session{})
	return result.RowsAffected, result.Error
}
