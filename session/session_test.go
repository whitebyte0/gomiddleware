package session

import (
	"testing"
	"time"
)

func TestSession_IsExpired(t *testing.T) {
	s := &Session{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if !s.IsExpired() {
		t.Error("expected expired")
	}

	s2 := &Session{ExpiresAt: time.Now().Add(1 * time.Hour)}
	if s2.IsExpired() {
		t.Error("expected not expired")
	}
}

func TestSession_TableName(t *testing.T) {
	s := Session{}
	if s.TableName() != "sessions" {
		t.Errorf("expected 'sessions', got %q", s.TableName())
	}
}

func TestNewSessionManager_DefaultExpiration(t *testing.T) {
	m := NewSessionManager(nil, 0)
	if m.expiration != 24*time.Hour {
		t.Errorf("expected 24h default, got %v", m.expiration)
	}
}

func TestNewSessionManager_CustomExpiration(t *testing.T) {
	m := NewSessionManager(nil, 8*time.Hour)
	if m.expiration != 8*time.Hour {
		t.Errorf("expected 8h, got %v", m.expiration)
	}
}
