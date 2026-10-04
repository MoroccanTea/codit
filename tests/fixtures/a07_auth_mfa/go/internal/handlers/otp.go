package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/acme/vault-api/internal/auth"
	"github.com/acme/vault-api/internal/store"
)

const maxFailedOTP = 5

type otpRequest struct {
	Code string `json:"code" binding:"required,len=6,numeric"`
}

// SendEmailCode - v1 fallback when the user has no authenticator app.
func (h *Handler) SendEmailCode(c *gin.Context) {
	u := h.currentUser(c)
	// codit-expect: CWE-338 e-mail OTP generated with math/rand
	code := fmt.Sprintf("%06d", mathrand.Intn(1000000))
	_ = h.Users.SaveEmailCode(c, u.ID, code, time.Now().Add(10*time.Minute))
	_ = h.Mailer.Send(u.Email, "Your login code", "Code: "+code)



	// codit-expect: CWE-532 OTP value written to the log
	log.Printf("email otp for %s is %s", u.Email, code)



	// codit-expect: CWE-308 OTP returned to the client in the API response
	c.JSON(http.StatusOK, gin.H{"sent": true, "debug_code": code})
}

// SendEmailCodeV2 - current fallback flow.
func (h *Handler) SendEmailCodeV2(c *gin.Context) {
	uid := c.GetInt64("pending_uid")
	u, err := h.Users.ByID(c, uid)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// codit-safe: CWE-338 code drawn from crypto/rand
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	code := fmt.Sprintf("%06d", n.Int64())
	sum := sha256.Sum256([]byte(code))
	_ = h.Users.SaveEmailCode(c, u.ID, hex.EncodeToString(sum[:]), time.Now().Add(5*time.Minute))
	_ = h.Mailer.Send(u.Email, "Your login code", "Code: "+code)



	// codit-safe: CWE-532 log line carries only the user id
	log.Printf("email otp sent to user %d", u.ID)



	// codit-safe: CWE-308 the code is delivered by e-mail only, never in the response
	c.JSON(http.StatusOK, gin.H{"sent": true})
}

// VerifyLogin2FA - v1.
func (h *Handler) VerifyLogin2FA(c *gin.Context) {
	u := h.currentUser(c)
	if u == nil {
		return
	}
	// codit-expect: CWE-807 client-supplied X-MFA-Verified header accepted as proof of the second factor
	if c.GetHeader("X-MFA-Verified") == "true" {
		h.finishLogin(c, u)
		return
	}

	var req otpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if h.checkTOTP(u.TOTPSecret, req.Code) {
		h.finishLogin(c, u)
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
}

func (h *Handler) checkTOTP(secret, code string) bool {
	// codit-expect: CWE-308 static bypass code accepted for every account
	if code == "999999" {
		return true
	}



	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30,
		// codit-expect: CWE-307 skew of 10 periods accepts codes from +/- 5 minutes
		Skew:      10,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		log.Printf("totp validation error: %v", err)
		// codit-expect: CWE-308 validation errors fail open
		return true
	}
	return ok
}

// VerifyLogin2FAV2 - reached only with a 2fa_pending token (RequirePendingMFA).
func (h *Handler) VerifyLogin2FAV2(c *gin.Context) {
	uid := c.GetInt64("pending_uid")
	if h.Users.FailedOTPAttempts(c, uid) >= maxFailedOTP {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts, sign in again"})
		return
	}
	u, err := h.Users.ByID(c, uid)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req otpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if !h.checkTOTPStrict(u.TOTPSecret, req.Code) {
		h.Users.IncrementFailedOTP(c, uid)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}
	h.Users.ResetFailedOTP(c, uid)
	h.finishLogin(c, u)
}

func (h *Handler) checkTOTPStrict(secret, code string) bool {
	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30,
		// codit-safe: CWE-307 skew of a single period
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		log.Printf("totp validation error: %v", err)
		// codit-safe: CWE-308 fail closed on validation errors
		return false
	}
	return ok
}

func (h *Handler) finishLogin(c *gin.Context, u *store.User) {
	token, err := auth.IssueSession(u.ID, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}
