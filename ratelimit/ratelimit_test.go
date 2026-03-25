package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestIPRateLimit_AllowsUnderLimit(t *testing.T) {
	r := gin.New()
	r.Use(IPRateLimit(5, time.Second))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestIPRateLimit_BlocksOverLimit(t *testing.T) {
	r := gin.New()
	// 3 requests burst, very low refill rate
	r.Use(IPRateLimit(3, 10*time.Minute))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	// Exhaust burst
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		r.ServeHTTP(w, req)
	}

	// Next request should be blocked
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	r.ServeHTTP(w, req)

	if w.Code != 429 {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Error("expected Retry-After header")
	}
}

func TestIPRateLimit_DifferentIPsIndependent(t *testing.T) {
	r := gin.New()
	r.Use(IPRateLimit(1, 10*time.Minute))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	// IP A — use its 1 burst token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:1111"
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("IP A first request: expected 200, got %d", w.Code)
	}

	// IP A — blocked
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:1111"
	r.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Fatalf("IP A second request: expected 429, got %d", w.Code)
	}

	// IP B — still allowed
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "2.2.2.2:2222"
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("IP B first request: expected 200, got %d", w.Code)
	}
}

func TestUserRateLimit_SkipsUnauthenticated(t *testing.T) {
	r := gin.New()
	r.Use(UserRateLimit(1, 10*time.Minute))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	// No userID in context — should not be rate limited
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("request %d: expected 200 (unauthenticated skip), got %d", i+1, w.Code)
		}
	}
}

func TestRateLimit_CustomKeyFunc(t *testing.T) {
	r := gin.New()
	// 2 burst, very low refill
	r.Use(RateLimit(0.001, 2, func(c *gin.Context) string {
		return c.GetHeader("X-API-Key")
	}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	// Key "aaa" — 2 allowed
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "aaa")
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("key aaa request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// Key "aaa" — 3rd blocked
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "aaa")
	r.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Fatalf("expected 429 for key aaa, got %d", w.Code)
	}

	// Key "bbb" — still allowed
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "bbb")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 for key bbb, got %d", w.Code)
	}
}
