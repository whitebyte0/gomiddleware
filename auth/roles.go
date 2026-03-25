package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole returns Gin middleware that checks if the authenticated user
// has one of the specified roles. Requires Auth() middleware to run first.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(c *gin.Context) {
		role, exists := GetRole(c)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			return
		}

		if !allowed[role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient permissions",
			})
			return
		}

		c.Next()
	}
}

// RequireAdmin is a shortcut for RequireRole("admin").
func RequireAdmin() gin.HandlerFunc {
	return RequireRole("admin")
}
