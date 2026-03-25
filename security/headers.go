package security

import "github.com/gin-gonic/gin"

// SecurityHeadersConfig allows overriding individual security headers.
// Empty string means use the default. Set to "-" to skip a header.
type SecurityHeadersConfig struct {
	FrameOptions       string // Default: "DENY"
	ContentTypeOptions string // Default: "nosniff"
	XSSProtection      string // Default: "1; mode=block"
	ReferrerPolicy     string // Default: "strict-origin-when-cross-origin"
	ContentSecurity    string // Default: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
	PermissionsPolicy  string // Default: "camera=(), microphone=(), geolocation=()"
	ForceHTTPS         bool   // When true, sets Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
}

var defaultHeaders = SecurityHeadersConfig{
	FrameOptions:       "DENY",
	ContentTypeOptions: "nosniff",
	XSSProtection:      "1; mode=block",
	ReferrerPolicy:     "strict-origin-when-cross-origin",
	ContentSecurity:    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
	PermissionsPolicy:  "camera=(), microphone=(), geolocation=()",
}

// SecurityHeaders returns Gin middleware that sets standard security headers.
// Call with no arguments for defaults, or pass a config to override.
func SecurityHeaders(cfg ...SecurityHeadersConfig) gin.HandlerFunc {
	h := defaultHeaders
	if len(cfg) > 0 {
		c := cfg[0]
		if c.FrameOptions != "" {
			h.FrameOptions = c.FrameOptions
		}
		if c.ContentTypeOptions != "" {
			h.ContentTypeOptions = c.ContentTypeOptions
		}
		if c.XSSProtection != "" {
			h.XSSProtection = c.XSSProtection
		}
		if c.ReferrerPolicy != "" {
			h.ReferrerPolicy = c.ReferrerPolicy
		}
		if c.ContentSecurity != "" {
			h.ContentSecurity = c.ContentSecurity
		}
		if c.PermissionsPolicy != "" {
			h.PermissionsPolicy = c.PermissionsPolicy
		}
		h.ForceHTTPS = c.ForceHTTPS
	}

	return func(c *gin.Context) {
		if h.FrameOptions != "-" {
			c.Header("X-Frame-Options", h.FrameOptions)
		}
		if h.ContentTypeOptions != "-" {
			c.Header("X-Content-Type-Options", h.ContentTypeOptions)
		}
		if h.XSSProtection != "-" {
			c.Header("X-XSS-Protection", h.XSSProtection)
		}
		if h.ReferrerPolicy != "-" {
			c.Header("Referrer-Policy", h.ReferrerPolicy)
		}
		if h.ContentSecurity != "-" {
			c.Header("Content-Security-Policy", h.ContentSecurity)
		}
		if h.PermissionsPolicy != "-" {
			c.Header("Permissions-Policy", h.PermissionsPolicy)
		}
		if h.ForceHTTPS {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Next()
	}
}
