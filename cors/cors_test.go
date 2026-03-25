package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSDev_AllowsAnyOrigin(t *testing.T) {
	r := gin.New()
	r.Use(CORSDev())
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://anything.example.com")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("CORSDev should allow any origin, got %q", got)
	}
}

func TestCORSProd_AllowsSpecifiedOrigin(t *testing.T) {
	r := gin.New()
	r.Use(CORSProd("https://vektor-x.com"))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://vektor-x.com")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://vektor-x.com" {
		t.Errorf("expected allowed origin, got %q", got)
	}
}

func TestCORSProd_BlocksUnknownOrigin(t *testing.T) {
	r := gin.New()
	r.Use(CORSProd("https://vektor-x.com"))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("CORSProd should block unknown origin, got %q", got)
	}
}

func TestCORSProd_PanicsWithNoOrigins(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("CORSProd should panic with no origins")
		}
	}()
	CORSProd()
}

func TestCORSProd_Preflight(t *testing.T) {
	r := gin.New()
	r.Use(CORSProd("https://vektor-x.com"))
	r.POST("/api", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/api", nil)
	req.Header.Set("Origin", "https://vektor-x.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Errorf("preflight expected 204, got %d", w.Code)
	}
}

func TestCORS_AllowedOrigin(t *testing.T) {
	r := gin.New()
	r.Use(CORS("http://localhost:3000"))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("expected allowed origin, got %q", got)
	}
}

func TestCORSWithConfig_Custom(t *testing.T) {
	r := gin.New()
	r.Use(CORSWithConfig(CORSConfig{
		AllowOrigins:     []string{"https://example.com"},
		AllowMethods:     []string{"GET"},
		AllowCredentials: true,
	}))
	r.GET("/", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("expected allowed origin, got %q", got)
	}
}
