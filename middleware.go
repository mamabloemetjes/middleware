package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/MonkyMars/gecho"

	"github.com/mamabloemetjes/backend/config"
	"github.com/mamabloemetjes/mdatabase"
)

// Claims represents JWT claims needed by middleware.
type Claims struct {
	JTI string
	Sub string
}

// ClaimsExtractor extracts JWT claims from a request.
type ClaimsExtractor interface {
	ExtractClaims(r *http.Request) (*Claims, error)
}

// CacheService provides cache operations needed by middleware.
type CacheService interface {
	IsTokenBlacklisted(jti string) (bool, error)
	DeleteUserFromCache(userID string) error
	IncrementRateLimit(clientIP, endpoint string, window time.Duration) (int, error)
}

// AuthService provides database access for authorization checks.
type AuthService interface {
	GetDB() *mdatabase.DB
}

// ResponseSender sends HTTP responses.
type ResponseSender func(*gecho.Response)

// MetricsCollector collects HTTP metrics.
type MetricsCollector interface {
	RecordRequest(method, path, status string, duration time.Duration)
}

// User represents a user for authorization checks.
type User struct {
	ID   string
	Role string
}

// AuthServiceWithUser provides user lookup for authorization.
type AuthServiceWithUser interface {
	AuthService
	GetUserByID(ctx context.Context, id string) (*User, error)
}

// Middleware holds the middleware components.
type Middleware struct {
	logger           *gecho.Logger
	authService      AuthServiceWithUser
	cacheService     CacheService
	cfg              *config.Config
	claimsExtractor  ClaimsExtractor
	responseSender   ResponseSender
	metricsCollector MetricsCollector
}

// NewMiddleware creates a new Middleware instance.
func NewMiddleware(cfg *config.Config, logger *gecho.Logger, db *mdatabase.DB,
	authService AuthServiceWithUser, cacheService CacheService,
	claimsExtractor ClaimsExtractor, responseSender ResponseSender,
	metricsCollector MetricsCollector) *Middleware {
	return &Middleware{
		logger:           logger,
		authService:      authService,
		cacheService:     cacheService,
		cfg:              cfg,
		claimsExtractor:  claimsExtractor,
		responseSender:   responseSender,
		metricsCollector: metricsCollector,
	}
}
