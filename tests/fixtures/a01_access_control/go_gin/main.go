package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	h := &Handlers{db: db}

	r := gin.Default()

	r.POST("/login", h.Login) // codit-safe: CWE-862 login is public by design

	r.GET("/api/v2/me", AuthMiddleware(), h.Me) // codit-safe: CWE-862 inline AuthMiddleware() handler

	api := r.Group("/api")
	api.Use(AuthMiddleware())
	{
		api.GET("/invoices/:id", h.GetInvoice)
		api.GET("/me/invoices/:id", h.GetMyInvoice)
		api.POST("/tickets/:id/escalate", h.EscalateTicket)
		api.POST("/tickets/:id/close", h.CloseTicket)
		api.GET("/files", h.Download)
		api.GET("/files/v2", h.SafeDownload)
	}

	admin := api.Group("/admin", RequireRole("admin"))
	{
		admin.GET("/users", h.ListUsers) // codit-safe: CWE-862 group inherits AuthMiddleware and adds RequireRole("admin")

		admin.DELETE("/users/:id", h.DeleteUser) // codit-safe: CWE-862,CWE-639 admin group; admins manage any account
	}

	// Registered on the root engine: none of the group middleware applies.
	r.POST("/admin/reindex", h.Reindex) // codit-expect: CWE-862 admin action on the root engine outside the protected groups

	// Ops shortcut for the cache layer (called from the runbook script).
	// It lives under /api/admin/ but is NOT part of the admin group.
	r.DELETE("/api/admin/cache", h.FlushCache) // codit-expect: CWE-862 path looks like the admin group but is registered on the root engine without middleware

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
