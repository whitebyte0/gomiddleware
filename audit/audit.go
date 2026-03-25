package audit

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/whitebyte0/gomiddleware/auth"
)

const ctxResourceType = "auditResourceType"

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	UserID       int64     `json:"user_id"`
	Email        string    `json:"email,omitempty"`
	Action       string    `json:"action"`        // created, updated, deleted, accessed
	ResourceType string    `json:"resource_type"`  // e.g. "user", "post", "comment"
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	Status       int       `json:"status"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	Body         string    `json:"body,omitempty"` // Request body (only for paths in LogBodyPaths)
	Timestamp    time.Time `json:"timestamp"`
}

// AuditStore persists audit entries. Implement with your DB, file, etc.
type AuditStore interface {
	Save(entry AuditEntry) error
}

// AuditConfig configures the audit middleware.
type AuditConfig struct {
	Store         AuditStore // Required: where to save entries
	SkipPaths     []string   // Paths to skip (e.g. "/health", "/ready")
	PublicPaths   []string   // Paths to log even if unauthenticated (e.g. "/api/auth/login")
	LogBodyPaths  []string   // Paths where request body is captured (e.g. "/api/auth/login", "/api/admin/*")
	MaxBodySize   int        // Max body bytes to capture (default: 4096)
}

// Audit returns Gin middleware that logs requests asynchronously.
// By default, only logs successful requests (status < 400) for authenticated users.
// Use PublicPaths to also log unauthenticated requests on specific routes.
// Use LogBodyPaths to capture request bodies on specific routes.
func Audit(cfg AuditConfig) gin.HandlerFunc {
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 4096
	}

	skip := toSet(cfg.SkipPaths)
	public := toSet(cfg.PublicPaths)
	logBody := toSet(cfg.LogBodyPaths)

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Buffer body before c.Next() if this path needs body logging
		var bodyBytes []byte
		if matchPath(path, logBody) {
			if c.Request.Body != nil {
				bodyBytes, _ = io.ReadAll(io.LimitReader(c.Request.Body, int64(cfg.MaxBodySize)))
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		c.Next()

		if skip[path] {
			return
		}
		if c.Writer.Status() >= 400 {
			return
		}

		userID, authenticated := auth.GetUserID(c)
		if !authenticated && !matchPath(path, public) {
			return
		}

		email, _ := auth.GetEmail(c)
		resourceType, _ := c.Get(ctxResourceType)
		rt, _ := resourceType.(string)

		entry := AuditEntry{
			UserID:       userID,
			Email:        email,
			Action:       actionFromMethod(c.Request.Method),
			ResourceType: rt,
			Method:       c.Request.Method,
			Path:         path,
			Status:       c.Writer.Status(),
			IPAddress:    c.ClientIP(),
			UserAgent:    c.Request.UserAgent(),
			Timestamp:    time.Now(),
		}

		if len(bodyBytes) > 0 {
			entry.Body = string(bodyBytes)
		}

		go cfg.Store.Save(entry)
	}
}

// ResourceType returns Gin middleware that tags the route with a resource type for audit logging.
func ResourceType(name string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxResourceType, name)
		c.Next()
	}
}

func actionFromMethod(method string) string {
	switch method {
	case "POST":
		return "created"
	case "PUT", "PATCH":
		return "updated"
	case "DELETE":
		return "deleted"
	default:
		return "accessed"
	}
}

func toSet(paths []string) map[string]bool {
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		m[p] = true
	}
	return m
}

// matchPath checks exact match or wildcard prefix match (e.g. "/api/admin/*")
func matchPath(path string, set map[string]bool) bool {
	if set[path] {
		return true
	}
	for p := range set {
		if len(p) > 0 && p[len(p)-1] == '*' {
			prefix := p[:len(p)-1]
			if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}
