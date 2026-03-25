# gomiddleware

Middleware package for Go + Gin.

## Install

```bash
go get github.com/whitebyte0/gomiddleware
```

## Security Headers

```go
import "github.com/whitebyte0/gomiddleware/security"

// Defaults (no HSTS)
router.Use(security.SecurityHeaders())

// Production — force HTTPS
router.Use(security.SecurityHeaders(security.SecurityHeadersConfig{
    ForceHTTPS: true,
}))

// Custom override (use "-" to skip a header)
router.Use(security.SecurityHeaders(security.SecurityHeadersConfig{
    FrameOptions:    "SAMEORIGIN",
    ContentSecurity: "-",  // skip CSP
    ForceHTTPS:      true,
}))
```

Default headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`.

## Recovery

Catches panics, logs full request context (method, path, IP, user agent, body, stack trace), returns 500 JSON.

```go
import "github.com/whitebyte0/gomiddleware/recovery"

// Default — logs to stderr
router.Use(recovery.Recovery(nil))

// Custom handler
router.Use(recovery.Recovery(func(c *gin.Context, err any, stack string) {
    myLogger.Error("panic", "error", err, "stack", stack)
}))
```

## CORS

Three levels: dev preset, production preset, full custom.

```go
import "github.com/whitebyte0/gomiddleware/cors"

// Development — allows all origins
router.Use(cors.CORSDev())

// Production — strict origin list, credentials, 24h preflight cache
router.Use(cors.CORSProd("https://vektor-x.com"))

// Full control — UseDefaults fills empty fields with sensible defaults
router.Use(cors.CORSWithConfig(cors.CORSConfig{
    AllowOrigins: []string{"https://example.com"},
    AllowMethods: []string{"GET", "POST"},
    UseDefaults:  true,
}))
```

## Rate Limiting

Token bucket algorithm via `golang.org/x/time/rate`. Per-key with automatic cleanup.

```go
import "github.com/whitebyte0/gomiddleware/ratelimit"

// By IP — 10 requests per minute
router.Use(ratelimit.IPRateLimit(10, time.Minute))

// By authenticated user — 100 requests per hour
router.Use(ratelimit.UserRateLimit(100, time.Hour))

// Custom key function
router.Use(ratelimit.RateLimit(1.0, 10, func(c *gin.Context) string {
    return c.GetHeader("X-API-Key")
}))

// Per-route
api.POST("/auth/login", ratelimit.IPRateLimit(5, time.Minute), loginHandler)
```

Returns `429 Too Many Requests` with `Retry-After` header when exceeded.

## Password Hashing

`Hasher` interface with bcrypt and Argon2id implementations.

```go
import "github.com/whitebyte0/gomiddleware/password"

// Bcrypt (default cost 12)
hasher := password.NewBcryptHasher()

// Argon2id (recommended for new projects)
hasher := password.NewArgon2idHasher()

// Both use the same interface
hash, err := hasher.Hash("password123")
ok, err := hasher.Verify("password123", hash)
```

## JWT

Generate, validate, refresh, and revoke JWT tokens.

```go
import "github.com/whitebyte0/gomiddleware/jwt"

m := jwt.NewJWTManager(jwt.JWTConfig{
    Secret:   "your-secret-minimum-32-bytes-long!!",
    Issuer:   "my-app",
    Audience: "my-app",
})

// Generate
token, err := m.Generate(jwt.GenerateInput{
    UserID: 42, Email: "user@test.com", Role: "admin",
    SessionToken: session.SessionToken,
})

// Validate
claims, err := m.Validate(token)

// Refresh (only expired tokens within refresh window)
newToken, err := m.Refresh(expiredToken)

// Revoke
m.Revoke(token, userID, "logout")
```

### Built-in GORM stores

```go
// Token revocation store
revokedStore := jwt.NewGORMRevokedTokenStore(db)

// Token version provider (reads token_version from users table)
versionProvider := jwt.NewGORMTokenVersionProvider(db)

m := jwt.NewJWTManager(jwt.JWTConfig{
    Secret:               "...",
    Issuer:               "my-app",
    Audience:             "my-app",
    RevokedTokenStore:    revokedStore,
    TokenVersionProvider: versionProvider,
})
```

Or implement `jwt.RevokedTokenStore` and `jwt.TokenVersionProvider` with your own storage.

### Config defaults

| Field | Default |
|-------|---------|
| Expiration | 1 hour |
| RefreshWindow | 24 hours |

## Sessions

GORM-backed database sessions with sliding window expiration.

```go
import "github.com/whitebyte0/gomiddleware/session"

sm := session.NewSessionManager(db, 24*time.Hour)

sess, err := sm.Create(userID, ipAddress, userAgent)  // login
sess, err := sm.Validate(sessionToken)                 // check
sm.UpdateActivity(sessionToken)                        // sliding window
sm.Delete(sessionToken)                                // single logout
sm.DeleteAll(userID)                                   // logout everywhere
sm.DeleteByID(sessionID, userID)                       // revoke specific
sessions, err := sm.List(userID)                       // list active
deleted, err := sm.CleanupExpired()                    // background cleanup
```

## Auth Middleware

Extracts Bearer token, validates, sets user context.

```go
import "github.com/whitebyte0/gomiddleware/auth"

// Required auth — returns 401 if missing/invalid
router.Use(auth.Auth(jwtManager))

// Optional auth — continues without context if no token
router.Use(auth.OptionalAuth(jwtManager))

// Access context in handlers
userID, ok := auth.GetUserID(c)
email, ok := auth.GetEmail(c)
role, ok := auth.GetRole(c)
sessionToken, ok := auth.GetSessionToken(c)
```

`jwt.JWTManager` implements `auth.TokenValidator` — pass it directly.

## Role-Based Access

```go
import "github.com/whitebyte0/gomiddleware/auth"

router.POST("/admin/users", auth.RequireRole("admin", "moderator"), handler)
router.DELETE("/admin/users/:id", auth.RequireAdmin(), handler)
```

Roles are strings — define your own.

## Audit

Async request logging with public path logging and body capture.

```go
import "github.com/whitebyte0/gomiddleware/audit"

router.Use(audit.Audit(audit.AuditConfig{
    Store:     &myAuditStore{db: db},
    SkipPaths: []string{"/health", "/ready"},

    // Log even without auth (e.g. login attempts)
    PublicPaths: []string{"/api/auth/login", "/api/auth/register"},

    // Capture request body on these paths (supports wildcards)
    LogBodyPaths: []string{"/api/auth/*", "/api/admin/*"},
    MaxBodySize:  4096,  // default 4KB
}))

// Tag routes with resource types
userRoutes := router.Group("/users")
userRoutes.Use(audit.ResourceType("user"))
```

Implement `audit.AuditStore`:

```go
type AuditStore interface {
    Save(entry AuditEntry) error
}
```

Action is auto-detected: POST→created, PUT/PATCH→updated, DELETE→deleted, GET→accessed.

Path matching supports exact (`"/api/auth/login"`) and wildcard (`"/api/admin/*"`).

## License

MIT
