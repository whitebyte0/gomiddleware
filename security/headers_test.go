package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestSecurityHeaders_Defaults(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)

	tests := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"X-XSS-Protection":      "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	}

	for header, expected := range tests {
		got := w.Header().Get(header)
		if got != expected {
			t.Errorf("%s: got %q, want %q", header, got, expected)
		}
	}

	// HSTS not set by default
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS should not be set by default, got %q", got)
	}
}

func TestSecurityHeaders_CustomOverride(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeaders(SecurityHeadersConfig{
		FrameOptions: "SAMEORIGIN",
		ForceHTTPS:   true,
	}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)

	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options: got %q, want SAMEORIGIN", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains; preload" {
		t.Errorf("HSTS: got %q, want max-age=31536000; includeSubDomains; preload", got)
	}
	// Other defaults should still be set
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options should still be default, got %q", got)
	}
}

func TestSecurityHeaders_Skip(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeaders(SecurityHeadersConfig{
		FrameOptions:   "-",
		XSSProtection:  "-",
		ContentSecurity: "-",
	}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)

	if got := w.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("X-Frame-Options should be skipped, got %q", got)
	}
	if got := w.Header().Get("X-XSS-Protection"); got != "" {
		t.Errorf("X-XSS-Protection should be skipped, got %q", got)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP should be skipped, got %q", got)
	}
	// These should still be set
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options should still be set, got %q", got)
	}
}
