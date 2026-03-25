package recovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRecovery_CatchesPanic(t *testing.T) {
	r := gin.New()
	r.Use(Recovery(nil))
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "Internal Server Error" {
		t.Errorf("expected error field, got %v", body)
	}
}

func TestRecovery_CustomHandler(t *testing.T) {
	var captured any
	var capturedStack string

	r := gin.New()
	r.Use(Recovery(func(c *gin.Context, err any, stack string) {
		captured = err
		capturedStack = stack
	}))
	r.GET("/panic", func(c *gin.Context) {
		panic("custom panic")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	if captured != "custom panic" {
		t.Errorf("expected captured panic, got %v", captured)
	}
	if capturedStack == "" {
		t.Error("expected stack trace")
	}
}

func TestRecovery_NoPanic(t *testing.T) {
	r := gin.New()
	r.Use(Recovery(nil))
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
