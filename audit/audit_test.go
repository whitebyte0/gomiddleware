package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/whitebyte0/gomiddleware/auth"
)

func init() { gin.SetMode(gin.TestMode) }

type mockAuditStore struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (s *mockAuditStore) Save(entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *mockAuditStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *mockAuditStore) last() AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[len(s.entries)-1]
}

func setupAuditTest(store *mockAuditStore, cfg AuditConfig) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, int64(42))
		c.Set(auth.CtxEmail, "test@test.com")
		c.Next()
	})
	cfg.Store = store
	r.Use(Audit(cfg))
	return r
}

func TestAudit_LogsSuccessfulRequest(t *testing.T) {
	store := &mockAuditStore{}
	r := setupAuditTest(store, AuditConfig{})
	r.POST("/api/users", ResourceType("user"), func(c *gin.Context) { c.Status(201) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/users", nil)
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 1 {
		t.Fatalf("expected 1 entry, got %d", store.count())
	}
	entry := store.last()
	if entry.UserID != 42 {
		t.Errorf("UserID: got %d", entry.UserID)
	}
	if entry.Action != "created" {
		t.Errorf("Action: got %s", entry.Action)
	}
	if entry.ResourceType != "user" {
		t.Errorf("ResourceType: got %s", entry.ResourceType)
	}
}

func TestAudit_SkipsFailedRequests(t *testing.T) {
	store := &mockAuditStore{}
	r := setupAuditTest(store, AuditConfig{})
	r.GET("/api/fail", func(c *gin.Context) { c.Status(404) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/fail", nil)
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 0 {
		t.Errorf("expected 0 entries, got %d", store.count())
	}
}

func TestAudit_SkipsPaths(t *testing.T) {
	store := &mockAuditStore{}
	r := setupAuditTest(store, AuditConfig{SkipPaths: []string{"/health"}})
	r.GET("/health", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 0 {
		t.Errorf("expected 0 entries, got %d", store.count())
	}
}

func TestAudit_SkipsUnauthenticated(t *testing.T) {
	store := &mockAuditStore{}
	r := gin.New()
	r.Use(Audit(AuditConfig{Store: store}))
	r.GET("/api/data", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/data", nil)
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 0 {
		t.Errorf("expected 0 entries for unauthenticated, got %d", store.count())
	}
}

func TestAudit_PublicPaths_LogsUnauthenticated(t *testing.T) {
	store := &mockAuditStore{}
	r := gin.New()
	r.Use(Audit(AuditConfig{
		Store:       store,
		PublicPaths: []string{"/api/auth/login"},
	}))
	r.POST("/api/auth/login", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/login", nil)
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 1 {
		t.Fatalf("expected 1 entry for public path, got %d", store.count())
	}
	if store.last().UserID != 0 {
		t.Errorf("expected UserID 0 for unauthenticated, got %d", store.last().UserID)
	}
}

func TestAudit_PublicPaths_Wildcard(t *testing.T) {
	store := &mockAuditStore{}
	r := gin.New()
	r.Use(Audit(AuditConfig{
		Store:       store,
		PublicPaths: []string{"/api/auth/*"},
	}))
	r.POST("/api/auth/register", func(c *gin.Context) { c.Status(201) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/register", nil)
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 1 {
		t.Fatalf("expected 1 entry for wildcard public path, got %d", store.count())
	}
}

func TestAudit_LogBodyPaths_CapturesBody(t *testing.T) {
	store := &mockAuditStore{}
	r := setupAuditTest(store, AuditConfig{
		LogBodyPaths: []string{"/api/auth/login"},
	})
	r.POST("/api/auth/login", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	body := `{"email":"test@test.com","password":"secret"}`
	req, _ := http.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 1 {
		t.Fatalf("expected 1 entry, got %d", store.count())
	}
	if store.last().Body != body {
		t.Errorf("Body: got %q, want %q", store.last().Body, body)
	}
}

func TestAudit_LogBodyPaths_NoBodyOnOtherPaths(t *testing.T) {
	store := &mockAuditStore{}
	r := setupAuditTest(store, AuditConfig{
		LogBodyPaths: []string{"/api/auth/login"},
	})
	r.POST("/api/users", func(c *gin.Context) { c.Status(201) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"test"}`))
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 1 {
		t.Fatalf("expected 1 entry, got %d", store.count())
	}
	if store.last().Body != "" {
		t.Errorf("expected empty body on non-logged path, got %q", store.last().Body)
	}
}

func TestAudit_LogBodyPaths_Wildcard(t *testing.T) {
	store := &mockAuditStore{}
	r := setupAuditTest(store, AuditConfig{
		LogBodyPaths: []string{"/api/admin/*"},
	})
	r.POST("/api/admin/settings", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	body := `{"key":"value"}`
	req, _ := http.NewRequest("POST", "/api/admin/settings", strings.NewReader(body))
	r.ServeHTTP(w, req)
	time.Sleep(50 * time.Millisecond)

	if store.count() != 1 {
		t.Fatalf("expected 1 entry, got %d", store.count())
	}
	if store.last().Body != body {
		t.Errorf("Body: got %q, want %q", store.last().Body, body)
	}
}

func TestAudit_ActionFromMethod(t *testing.T) {
	tests := map[string]string{
		"POST": "created", "PUT": "updated", "PATCH": "updated",
		"DELETE": "deleted", "GET": "accessed",
	}
	for method, expected := range tests {
		if got := actionFromMethod(method); got != expected {
			t.Errorf("%s: got %s, want %s", method, got, expected)
		}
	}
}

func TestMatchPath_Exact(t *testing.T) {
	set := toSet([]string{"/api/login"})
	if !matchPath("/api/login", set) { t.Error("expected match") }
	if matchPath("/api/other", set) { t.Error("expected no match") }
}

func TestMatchPath_Wildcard(t *testing.T) {
	set := toSet([]string{"/api/admin/*"})
	if !matchPath("/api/admin/users", set) { t.Error("expected match") }
	if !matchPath("/api/admin/settings", set) { t.Error("expected match") }
	if matchPath("/api/public", set) { t.Error("expected no match") }
}
