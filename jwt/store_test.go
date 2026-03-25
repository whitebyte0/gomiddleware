package jwt

import (
	"testing"
)

func TestRevokedToken_TableName(t *testing.T) {
	r := RevokedToken{}
	if r.TableName() != "revoked_tokens" {
		t.Errorf("expected 'revoked_tokens', got %q", r.TableName())
	}
}

func TestTokenVersionUser_TableName(t *testing.T) {
	u := tokenVersionUser{}
	if u.TableName() != "users" {
		t.Errorf("expected 'users', got %q", u.TableName())
	}
}

// Interface compliance — compile-time check
var _ RevokedTokenStore = (*GORMRevokedTokenStore)(nil)
var _ TokenVersionProvider = (*GORMTokenVersionProvider)(nil)
