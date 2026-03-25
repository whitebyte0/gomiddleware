package recovery

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// RecoveryFunc is called when a panic is recovered.
// Receives the panic value and stack trace.
type RecoveryFunc func(c *gin.Context, err any, stack string)

// Recovery returns Gin middleware that recovers from panics and returns a 500 JSON response.
// Pass nil for default behavior (logs full request + stack trace to stderr).
// Pass a custom RecoveryFunc to handle panics your way (e.g. structured logging, alerting).
func Recovery(fn RecoveryFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Buffer the request body so it's available after panic
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		defer func() {
			if err := recover(); err != nil {
				stack := string(debug.Stack())

				if fn != nil {
					fn(c, err, stack)
				} else {
					fmt.Fprintf(gin.DefaultErrorWriter,
						"[gomiddleware] PANIC RECOVERED\n"+
							"  Error:  %v\n"+
							"  Method: %s\n"+
							"  Path:   %s\n"+
							"  IP:     %s\n"+
							"  Agent:  %s\n"+
							"  Body:   %s\n"+
							"  Stack:\n%s\n",
						err,
						c.Request.Method,
						c.Request.URL.String(),
						c.ClientIP(),
						c.Request.UserAgent(),
						string(bodyBytes),
						stack,
					)
				}

				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":   "Internal Server Error",
					"message": "An unexpected error occurred",
				})
			}
		}()
		c.Next()
	}
}
