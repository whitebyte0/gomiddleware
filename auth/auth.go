package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/whitebyte0/gomiddleware/jwt"
)

// Context keys for auth values.
const (
	CtxUserID       = "userID"
	CtxEmail        = "userEmail"
	CtxRole         = "userRole"
	CtxSessionToken = "sessionToken"
	CtxRawToken     = "rawToken"
)

// TokenValidator validates a JWT token and returns claims.
type TokenValidator interface {
	Validate(token string) (*jwt.Claims, error)
}

// Auth returns Gin middleware that requires a valid Bearer token.
func Auth(validator TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Missing or invalid authorization header",
			})
			return
		}

		claims, err := validator.Validate(token)
		if err != nil {
			msg := "Invalid token"
			if err == jwt.ErrExpiredToken {
				msg = "Token has expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": msg,
			})
			return
		}

		setAuthContext(c, claims, token)
		c.Next()
	}
}

// OptionalAuth validates the token if present but doesn't abort if missing.
func OptionalAuth(validator TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			c.Next()
			return
		}

		claims, err := validator.Validate(token)
		if err != nil {
			c.Next()
			return
		}

		setAuthContext(c, claims, token)
		c.Next()
	}
}

// --- Context helpers ---

func GetUserID(c *gin.Context) (int64, bool) {
	id, exists := c.Get(CtxUserID)
	if !exists {
		return 0, false
	}
	return id.(int64), true
}

func GetEmail(c *gin.Context) (string, bool) {
	v, exists := c.Get(CtxEmail)
	if !exists {
		return "", false
	}
	return v.(string), true
}

func GetRole(c *gin.Context) (string, bool) {
	v, exists := c.Get(CtxRole)
	if !exists {
		return "", false
	}
	return v.(string), true
}

func GetSessionToken(c *gin.Context) (string, bool) {
	v, exists := c.Get(CtxSessionToken)
	if !exists {
		return "", false
	}
	return v.(string), true
}

func GetRawToken(c *gin.Context) (string, bool) {
	v, exists := c.Get(CtxRawToken)
	if !exists {
		return "", false
	}
	return v.(string), true
}

// --- internal ---

func extractBearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func setAuthContext(c *gin.Context, claims *jwt.Claims, rawToken string) {
	c.Set(CtxUserID, claims.UserID)
	c.Set(CtxEmail, claims.Email)
	c.Set(CtxRole, claims.Role)
	c.Set(CtxSessionToken, claims.SessionToken)
	c.Set(CtxRawToken, rawToken)
}
