package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/acme/vault-api/internal/store"
)

// UpdateProfile - v1.
func (h *Handler) UpdateProfile(c *gin.Context) {
	u := h.currentUser(c)
	if u == nil {
		return
	}
	// codit-expect: CWE-915 request body bound straight onto the user model (totp_enabled, is_admin writable)
	if err := c.ShouldBindJSON(u); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	_ = h.Users.Save(c, u)
	c.JSON(http.StatusOK, u)
}

type profileUpdate struct {
	DisplayName string `json:"display_name" binding:"max=80"`
}

// UpdateProfileV2 binds a narrow DTO.
func (h *Handler) UpdateProfileV2(c *gin.Context) {
	u := h.currentUser(c)
	if u == nil {
		return
	}
	var in profileUpdate
	// codit-safe: CWE-915 only display_name can be changed through this DTO
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	u.DisplayName = in.DisplayName
	_ = h.Users.Save(c, u)
	c.JSON(http.StatusOK, gin.H{"display_name": u.DisplayName})
}



// codit-expect: CWE-308 TOTP disabled with only the bearer token (no password or current code)
func (h *Handler) DisableTOTP(c *gin.Context) {
	u := h.currentUser(c)
	if u == nil {
		return
	}
	u.TOTPEnabled = false
	u.TOTPSecret = ""
	_ = h.Users.Save(c, u)
	c.Status(http.StatusNoContent)
}

type disableTOTPRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required,len=6,numeric"`
}

// codit-safe: CWE-308 disabling TOTP re-verifies the password and a current code
func (h *Handler) DisableTOTPV2(c *gin.Context) {
	u := h.currentUser(c)
	if u == nil {
		return
	}
	var req disableTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "re-authentication failed"})
		return
	}
	ok, err := totp.ValidateCustom(req.Code, u.TOTPSecret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "re-authentication failed"})
		return
	}
	u.TOTPEnabled = false
	u.TOTPSecret = ""
	_ = h.Users.Save(c, u)
	c.Status(http.StatusNoContent)
}

var _ = store.User{}
