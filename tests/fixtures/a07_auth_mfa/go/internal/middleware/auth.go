package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/acme/vault-api/internal/auth"
)

func bearer(c *gin.Context) string {
	return strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
}

// RequireAuth protects the v1 API group.
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.Parse(bearer(c))
		// codit-expect: CWE-308 any valid token passes (purpose never checked), so a 2fa_pending token opens every v1 route
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("uid", claims.UserID)
		c.Next()
	}
}



// RequireFullAuth protects the v2 API group.
func RequireFullAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.Parse(bearer(c))
		// codit-safe: CWE-308 pending-2FA tokens are rejected outside the 2FA endpoint
		if err != nil || claims.Purpose != auth.PurposeSession {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("uid", claims.UserID)
		c.Next()
	}
}

// RequirePendingMFA only admits the short-lived token issued by the password step.
func RequirePendingMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.Parse(bearer(c))
		if err != nil || claims.Purpose != auth.PurposeMFAPending {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("pending_uid", claims.UserID)
		c.Next()
	}
}
