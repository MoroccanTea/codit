package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/acme/vault-api/internal/handlers"
	"github.com/acme/vault-api/internal/middleware"
	"github.com/acme/vault-api/internal/store"
)

// perKeyLimiter allows n requests per window for each client IP.
func perKeyLimiter(n int, window time.Duration) gin.HandlerFunc {
	var mu sync.Mutex
	limiters := map[string]*rate.Limiter{}
	return func(c *gin.Context) {
		mu.Lock()
		l, ok := limiters[c.ClientIP()]
		if !ok {
			l = rate.NewLimiter(rate.Every(window/time.Duration(n)), n)
			limiters[c.ClientIP()] = l
		}
		mu.Unlock()
		if !l.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "slow down"})
			return
		}
		c.Next()
	}
}

func main() {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	h := &handlers.Handler{Users: &store.UserStore{DB: db}}

	r := gin.Default()
	r.POST("/v1/login", h.Login)
	r.POST("/v1/register", h.Register)

	v1 := r.Group("/v1", middleware.RequireAuth())
	v1.POST("/login/2fa/email", h.SendEmailCode)



	// codit-expect: CWE-307 OTP verification route with no rate limit (handler counts no failures either)
	v1.POST("/login/2fa", h.VerifyLogin2FA)



	v1.PATCH("/me", h.UpdateProfile)
	v1.DELETE("/me/totp", h.DisableTOTP)

	r.POST("/v2/login", perKeyLimiter(10, time.Minute), h.LoginV2)
	r.POST("/v2/register", perKeyLimiter(5, time.Minute), h.RegisterV2)

	pending := r.Group("/v2/login/2fa", middleware.RequirePendingMFA())
	pending.POST("/email", perKeyLimiter(3, 10*time.Minute), h.SendEmailCodeV2)



	// codit-safe: CWE-307 per-IP limiter on the route and a 5-failure lockout in the handler
	pending.POST("", perKeyLimiter(5, time.Minute), h.VerifyLogin2FAV2)



	v2 := r.Group("/v2", middleware.RequireFullAuth())
	v2.PATCH("/me", h.UpdateProfileV2)
	v2.DELETE("/me/totp", h.DisableTOTPV2)

	log.Fatal(r.Run(":8080"))
}
