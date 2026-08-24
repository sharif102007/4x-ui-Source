package controller

import (
	"net/http"

	"github.com/sharif102007/4x-ui/v2/web/service"
	"github.com/sharif102007/4x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// APIController handles the main API routes for the 4x-ui panel, including inbounds and server management.
type APIController struct {
	BaseController
	inboundController *InboundController
	serverController  *ServerController
	Tgbot             service.Tgbot
}

// NewAPIController creates a new APIController instance and initializes its routes.
func NewAPIController(g *gin.RouterGroup, customGeo *service.CustomGeoService) *APIController {
	a := &APIController{}
	a.initRouter(g, customGeo)
	return a
}

// checkAPIAuth is a middleware that returns 404 for unauthenticated API requests
// to hide the existence of API endpoints from unauthorized users
func (a *APIController) checkAPIAuth(c *gin.Context) {
	if !session.IsLogin(c) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if !service.LicenseRuntimeAllowed() {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "msg": "4x-ui license is not active"})
		return
	}
	c.Next()
}

// initRouter sets up the API routes for inbounds, server, and other endpoints.
func (a *APIController) initRouter(g *gin.RouterGroup, customGeo *service.CustomGeoService) {
	// Main API group
	api := g.Group("/panel/api")
	api.Use(a.checkAPIAuth)

	// Inbounds API
	inbounds := api.Group("/inbounds")
	a.inboundController = NewInboundController(inbounds)

	// Server API
	server := api.Group("/server")
	a.serverController = NewServerController(server)

	NewCustomGeoController(api.Group("/custom-geo"), customGeo)

	// SSH Manager API
	NewSshController(api)

	// Paid license status shown on the Overview page. The full key is never exposed.
	api.GET("/license/status", func(c *gin.Context) {
		jsonObj(c, (service.LicenseService{}).Status(), nil)
	})

	// Extra routes
	api.GET("/backuptotgbot", a.BackuptoTgbot)
}

// BackuptoTgbot sends a backup of the panel data to Telegram bot admins.
func (a *APIController) BackuptoTgbot(c *gin.Context) {
	a.Tgbot.SendBackupToAdmins()
}
