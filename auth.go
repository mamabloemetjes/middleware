package middleware

import (
	"context"
	"net/http"

	"github.com/MonkyMars/gecho"
)

// Context keys for storing user data in request context
type contextKey string

const (
	UserContextKey   contextKey = "user"
	ClaimsContextKey contextKey = "claims"
)

// UserAuthMiddleware protects routes to only logged-in users
func (mw *Middleware) UserAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := mw.claimsExtractor.ExtractClaims(r)
		if err != nil {
			mw.logger.Warn("Failed to extract claims from request", gecho.Field("error", err))
			mw.responseSender(gecho.Unauthorized(w, gecho.WithMessage("error.auth.invalidOrMissingAccessToken")))
			return
		}

		// Check if token is revoked
		isRevoked, err := mw.cacheService.IsTokenBlacklisted(claims.JTI)
		if err != nil {
			mw.logger.Error("Failed to check if token is revoked", gecho.Field("error", err))
			mw.responseSender(gecho.InternalServerError(w, gecho.WithMessage("error.internalServerError")))
			return
		}
		if isRevoked {
			mw.logger.Warn("Revoked token used for authentication", gecho.Field("token_id", claims.JTI))

			// Revoke user cache
			if err = mw.cacheService.DeleteUserFromCache(claims.Sub); err != nil {
				mw.logger.Error("Failed to revoke user cache for revoked token", gecho.Field("error", err), gecho.Field("user_id", claims.Sub))
			} else {
				mw.logger.Debug("User cache revoked for revoked token", gecho.Field("user_id", claims.Sub))
			}
			mw.responseSender(gecho.Unauthorized(w, gecho.WithMessage("error.auth.accessTokenRevoked")))
			return
		}

		// Add user and claims to request context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)

		// Continue to next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminAuthMiddleware protects routes to only admin users
// Must be used after UserAuthMiddleware
func (mw *Middleware) AdminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get claims from context (already validated by UserAuthMiddleware)
		claims, ok := GetClaimsFromContext(r.Context())
		if !ok {
			mw.logger.Error("Claims not found in context - UserAuthMiddleware must be used before AdminAuthMiddleware")
			mw.responseSender(gecho.Unauthorized(w, gecho.WithMessage("error.auth.invalidOrMissingAccessToken")))
			return
		}

		// Read the current role from the database. The token role is only a
		// hint; relying on it would allow an old admin token to survive a
		// demotion and makes authorization dependent on token claims.
		user, err := mw.authService.GetUserByID(r.Context(), claims.Sub)
		if err != nil {
			mw.logger.Warn("Admin authorization user lookup failed",
				gecho.Field("error", err),
				gecho.Field("user_id", claims.Sub),
			)
			mw.responseSender(gecho.Forbidden(w, gecho.WithMessage("error.auth.adminAccessRequired")))
			return
		}

		if user.Role != "admin" {
			mw.logger.Warn("Non-admin user attempted to access admin route",
				gecho.Field("user_id", claims.Sub),
				gecho.Field("role", user.Role),
			)
			mw.responseSender(gecho.Forbidden(w, gecho.WithMessage("error.auth.adminAccessRequired")))
			return
		}

		// User is admin, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext is a helper function to extract the user from request context
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey).(*User)
	return user, ok
}

// GetClaimsFromContext is a helper function to extract the claims from request context
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok
}
