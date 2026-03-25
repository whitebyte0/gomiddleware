package ratelimit

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimitKeyFunc extracts the rate limit key from a request.
// Return empty string to skip rate limiting for that request.
type RateLimitKeyFunc func(c *gin.Context) string

type rateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
	keyFunc  RateLimitKeyFunc
}

// RateLimit returns Gin middleware that limits requests using a token bucket algorithm.
// r: requests per second. burst: max burst size. keyFunc: extracts the rate limit key.
func RateLimit(r float64, burst int, keyFunc RateLimitKeyFunc) gin.HandlerFunc {
	rl := &rateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(r),
		burst:    burst,
		keyFunc:  keyFunc,
	}

	// Background cleanup of stale limiters every 5 minutes
	go rl.cleanup()

	return rl.handle
}

// IPRateLimit returns rate limiting middleware keyed by client IP.
// max: maximum requests allowed in the window. window: time duration.
func IPRateLimit(max int, window time.Duration) gin.HandlerFunc {
	r := float64(max) / window.Seconds()
	return RateLimit(r, max, func(c *gin.Context) string {
		return c.ClientIP()
	})
}

// UserRateLimit returns rate limiting middleware keyed by authenticated user ID.
// Requires auth middleware to set "userID" in context. Skips if not authenticated.
func UserRateLimit(max int, window time.Duration) gin.HandlerFunc {
	r := float64(max) / window.Seconds()
	return RateLimit(r, max, func(c *gin.Context) string {
		if id, exists := c.Get("userID"); exists {
			return fmt.Sprintf("user:%v", id)
		}
		return ""
	})
}

func (rl *rateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists = rl.limiters[key]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters[key] = limiter
	return limiter
}

func (rl *rateLimiter) handle(c *gin.Context) {
	key := rl.keyFunc(c)
	if key == "" {
		c.Next()
		return
	}

	limiter := rl.getLimiter(key)

	if !limiter.Allow() {
		c.Header("Retry-After", "1")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error":   "Too Many Requests",
			"message": "Rate limit exceeded. Try again later.",
		})
		return
	}

	c.Next()
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		// Remove limiters that have full tokens (idle clients)
		for key, limiter := range rl.limiters {
			if limiter.Tokens() >= float64(rl.burst) {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}
