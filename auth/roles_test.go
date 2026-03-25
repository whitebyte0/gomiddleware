package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupRoleTest(role string) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if role != "" {
			c.Set(CtxRole, role)
		}
		c.Next()
	})
	return r
}

func TestRequireRole_Allowed(t *testing.T) {
	r := setupRoleTest("admin")
	r.GET("/", RequireRole("admin", "moderator"), func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("expected 200, got %d", w.Code) }
}

func TestRequireRole_Forbidden(t *testing.T) {
	r := setupRoleTest("viewer")
	r.GET("/", RequireRole("admin", "moderator"), func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 403 { t.Fatalf("expected 403, got %d", w.Code) }
}

func TestRequireRole_NoAuth(t *testing.T) {
	r := setupRoleTest("")
	r.GET("/", RequireRole("admin"), func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("expected 401, got %d", w.Code) }
}

func TestRequireAdmin(t *testing.T) {
	r := setupRoleTest("admin")
	r.GET("/", RequireAdmin(), func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("expected 200, got %d", w.Code) }
}

func TestRequireAdmin_NotAdmin(t *testing.T) {
	r := setupRoleTest("moderator")
	r.GET("/", RequireAdmin(), func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	r.ServeHTTP(w, req)
	if w.Code != 403 { t.Fatalf("expected 403, got %d", w.Code) }
}
