package main

import (
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const uploadDir = "/srv/billing/uploads"

type Handlers struct {
	db *gorm.DB
}

type Invoice struct {
	ID     uint   `json:"id"`
	UserID string `json:"-"`
	Total  int64  `json:"total"`
}

type Ticket struct {
	ID     uint   `json:"id"`
	Status string `json:"status"`
}

type User struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}

func (h *Handlers) GetInvoice(c *gin.Context) {
	var inv Invoice
	if err := h.db.First(&inv, c.Param("id")).Error; err != nil { // codit-expect: CWE-639 invoice loaded by path id without a user_id condition
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, inv)
}

func (h *Handlers) GetMyInvoice(c *gin.Context) {
	var inv Invoice
	uid := c.GetString("userID")
	if err := h.db.Where("id = ? AND user_id = ?", c.Param("id"), uid).First(&inv).Error; err != nil { // codit-safe: CWE-639 query bound to the verified userID
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, inv)
}

func (h *Handlers) EscalateTicket(c *gin.Context) {
	if c.GetHeader("X-Role") != "supervisor" { // codit-expect: CWE-807 role taken from a client-supplied header
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	h.db.Model(&Ticket{}).Where("id = ?", c.Param("id")).Update("status", "escalated")
	c.Status(http.StatusNoContent)
}

func (h *Handlers) CloseTicket(c *gin.Context) {
	if c.GetString("role") != "supervisor" { // codit-safe: CWE-807 role set by AuthMiddleware from verified JWT claims
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	h.db.Model(&Ticket{}).Where("id = ?", c.Param("id")).Update("status", "closed")
	c.Status(http.StatusNoContent)
}

func (h *Handlers) Download(c *gin.Context) {
	c.File(filepath.Join(uploadDir, c.Query("name"))) // codit-expect: CWE-22 query parameter joined into the file path, ../ escapes uploadDir
}

func (h *Handlers) SafeDownload(c *gin.Context) {
	c.FileFromFS(c.Query("name"), gin.Dir(uploadDir, false)) // codit-safe: CWE-22 http.FileSystem rooted at uploadDir cleans and confines the path
}

func (h *Handlers) Login(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "use the identity provider"})
}

func (h *Handlers) Me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.GetString("userID")})
}

func (h *Handlers) ListUsers(c *gin.Context) {
	var users []User
	h.db.Order("email").Find(&users)
	c.JSON(http.StatusOK, users)
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	h.db.Delete(&User{}, c.Param("id"))
	c.Status(http.StatusNoContent)
}

func (h *Handlers) Reindex(c *gin.Context) {
	go rebuildSearchIndex(h.db)
	c.Status(http.StatusAccepted)
}

func (h *Handlers) FlushCache(c *gin.Context) {
	flushAllCaches()
	c.Status(http.StatusNoContent)
}

func rebuildSearchIndex(db *gorm.DB) {}

func flushAllCaches() {}
