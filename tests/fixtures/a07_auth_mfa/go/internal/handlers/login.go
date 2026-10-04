package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/acme/vault-api/internal/auth"
	"github.com/acme/vault-api/internal/store"
)

type Mailer interface {
	Send(to, subject, body string) error
}

type Handler struct {
	Users  *store.UserStore
	Mailer Mailer
}

func (h *Handler) currentUser(c *gin.Context) *store.User {
	u, err := h.Users.ByID(c, c.GetInt64("uid"))
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return nil
	}
	return u
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login is the v1 endpoint used by the legacy mobile app.
func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	u, err := h.Users.ByEmail(c, req.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}



	// codit-expect: CWE-308 full session JWT issued at the password step; the client is merely told mfa_required
	token, _ := auth.IssueLegacySession(u.ID)
	c.JSON(http.StatusOK, gin.H{"token": token, "mfa_required": u.TOTPEnabled})
}

// LoginV2 only hands out a purpose-scoped token until the second factor is verified.
func (h *Handler) LoginV2(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	u, err := h.Users.ByEmail(c, req.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if u.TOTPEnabled {
		// codit-safe: CWE-308 only a 5-minute 2fa_pending token (purpose-scoped) before the code is verified
		pending, err := auth.IssueMFAPending(u.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"mfa_required": true, "mfa_token": pending})
		return
	}
	token, err := auth.IssueSession(u.ID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

type registerRequest struct {
	Email string `json:"email" binding:"required,email"`
	// codit-expect: CWE-521 6-character minimum password length
	Password string `json:"password" binding:"required,min=6"`
}



type registerRequestV2 struct {
	Email string `json:"email" binding:"required,email"`
	// codit-safe: CWE-521 12-character minimum password length
	Password string `json:"password" binding:"required,min=12,max=128"`
}

func (h *Handler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// codit-expect: CWE-916 bcrypt cost 4 (minimum) makes offline cracking cheap
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 4)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}
	_ = h.Users.Create(c, req.Email, hash)
	c.Status(http.StatusCreated)
}

func (h *Handler) RegisterV2(c *gin.Context) {
	var req registerRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}
	// codit-safe: CWE-916 bcrypt cost 12
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}
	_ = h.Users.Create(c, req.Email, hash)
	c.Status(http.StatusCreated)
}
