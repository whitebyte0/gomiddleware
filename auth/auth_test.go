package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/whitebyte0/gomiddleware/jwt"
)

func init() { gin.SetMode(gin.TestMode) }

type mockValidator struct {
	claims *jwt.Claims
	err    error
}

func (v *mockValidator) Validate(token string) (*jwt.Claims, error) {
	if v.err != nil {
		return nil, v.err
	}
	return v.claims, nil
}

func TestAuth_ValidToken(t *testing.T) {
	v := &mockValidator{claims: &jwt.Claims{UserID: 42, Email: "test@test.com", Role: "admin", SessionToken: "sess-123"}}

	r := gin.New()
	r.Use(Auth(v))
	r.GET("/", func(c *gin.Context) {
		id, _ := GetUserID(c)
		email, _ := GetEmail(c)
		role, _ := GetRole(c)
		sess, _ := GetSessionToken(c)
		raw, _ := GetRawToken(c)

		if id != 42 { t.Errorf("UserID: got %d", id) }
		if email != "test@test.com" { t.Errorf("Email: got %s", email) }
		if role != "admin" { t.Errorf("Role: got %s", role) }
		if sess != "sess-123" { t.Errorf("SessionToken: got %s", sess) }
		if raw != "valid-token" { t.Errorf("RawToken: got %s", raw) }
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	r.ServeHTTP(w, req)

	if w.Code != 200 { t.Fatalf("expected 200, got %d", w.Code) }
}

func TestAuth_MissingToken(t *testing.T) {
	r := gin.New()
	r.Use(Auth(&mockValidator{}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("expected 401, got %d", w.Code) }
}

func TestAuth_InvalidToken(t *testing.T) {
	r := gin.New()
	r.Use(Auth(&mockValidator{err: jwt.ErrInvalidToken}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("expected 401, got %d", w.Code) }
}

func TestAuth_ExpiredToken(t *testing.T) {
	r := gin.New()
	r.Use(Auth(&mockValidator{err: jwt.ErrExpiredToken}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer expired")
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("expected 401, got %d", w.Code) }
}

func TestOptionalAuth_WithToken(t *testing.T) {
	v := &mockValidator{claims: &jwt.Claims{UserID: 10, Email: "opt@test.com", Role: "user"}}
	r := gin.New()
	r.Use(OptionalAuth(v))
	r.GET("/", func(c *gin.Context) {
		id, exists := GetUserID(c)
		if !exists || id != 10 { t.Errorf("expected UserID 10") }
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("expected 200, got %d", w.Code) }
}

func TestOptionalAuth_WithoutToken(t *testing.T) {
	r := gin.New()
	r.Use(OptionalAuth(&mockValidator{}))
	r.GET("/", func(c *gin.Context) {
		_, exists := GetUserID(c)
		if exists { t.Error("expected no UserID") }
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("expected 200, got %d", w.Code) }
}

func TestOptionalAuth_InvalidToken(t *testing.T) {
	r := gin.New()
	r.Use(OptionalAuth(&mockValidator{err: jwt.ErrInvalidToken}))
	r.GET("/", func(c *gin.Context) {
		_, exists := GetUserID(c)
		if exists { t.Error("expected no UserID") }
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("expected 200, got %d", w.Code) }
}

func TestAuth_BadFormat(t *testing.T) {
	r := gin.New()
	r.Use(Auth(&mockValidator{}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("expected 401, got %d", w.Code) }
}
