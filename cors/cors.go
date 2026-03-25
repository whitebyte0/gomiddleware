package cors

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSConfig allows customizing CORS behavior.
// When UseDefaults is false, only the fields you set are used (no auto-fill).
// When UseDefaults is true, empty fields are filled with sensible defaults.
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
	UseDefaults      bool // When true, fills empty fields with defaults
}

// CORSDev returns a permissive CORS middleware for development.
// Allows all origins, all methods, credentials enabled.
func CORSDev() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

// CORSProd returns a strict CORS middleware for production.
// Only specified origins are allowed. Credentials enabled. Preflight cached 24h.
func CORSProd(allowedOrigins ...string) gin.HandlerFunc {
	if len(allowedOrigins) == 0 {
		panic("gomiddleware: CORSProd requires at least one allowed origin")
	}
	return cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
	})
}

// CORS returns Gin CORS middleware with allowed origins.
// For presets use CORSDev() or CORSProd(). For full control use CORSWithConfig().
func CORS(allowedOrigins ...string) gin.HandlerFunc {
	return CORSWithConfig(CORSConfig{
		AllowOrigins: allowedOrigins,
	})
}

// CORSWithConfig returns Gin CORS middleware with full configuration.
func CORSWithConfig(cfg CORSConfig) gin.HandlerFunc {
	if cfg.UseDefaults {
		if len(cfg.AllowOrigins) == 0 {
			cfg.AllowOrigins = []string{"*"}
		}
		if len(cfg.AllowMethods) == 0 {
			cfg.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		}
		if len(cfg.AllowHeaders) == 0 {
			cfg.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
		}
		if len(cfg.ExposeHeaders) == 0 {
			cfg.ExposeHeaders = []string{"Content-Length"}
		}
		if cfg.MaxAge == 0 {
			cfg.MaxAge = 12 * time.Hour
		}
	}

	return cors.New(cors.Config{
		AllowOrigins:     cfg.AllowOrigins,
		AllowMethods:     cfg.AllowMethods,
		AllowHeaders:     cfg.AllowHeaders,
		ExposeHeaders:    cfg.ExposeHeaders,
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           cfg.MaxAge,
	})
}
