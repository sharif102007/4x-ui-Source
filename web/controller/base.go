// Package controller provides HTTP request handlers and controllers for the 4x-ui web management panel.
// It handles routing, authentication, and API endpoints for managing Xray inbounds, settings, and more.
package controller

import (
	"net/http"

	"github.com/sharif102007/4x-ui/v2/logger"
	"github.com/sharif102007/4x-ui/v2/web/locale"
	"github.com/sharif102007/4x-ui/v2/web/service"
	"github.com/sharif102007/4x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// BaseController provides common functionality for all controllers, including authentication checks.
type BaseController struct{}

// checkLogin is a middleware that verifies user authentication and handles unauthorized access.
func (a *BaseController) checkLogin(c *gin.Context) {
	if !session.IsLogin(c) {
		if isAjax(c) {
			pureJsonMsg(c, http.StatusUnauthorized, false, I18nWeb(c, "pages.login.loginAgain"))
		} else {
			c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
		}
		c.Abort()
	} else {
		c.Next()
	}
}

// checkLicense blocks paid panel routes when the local signed license cache is
// not currently valid. The public /license activation route is intentionally
// outside this middleware.
func (a *BaseController) checkLicense(c *gin.Context) {
	if service.LicenseRuntimeAllowed() {
		c.Next()
		return
	}
	if isAjax(c) {
		pureJsonMsg(c, http.StatusForbidden, false, "4x-ui license is not active")
	} else {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"license")
	}
	c.Abort()
}

// I18nWeb retrieves an internationalized message for the web interface based on the current locale.
func I18nWeb(c *gin.Context, name string, params ...string) string {
	anyfunc, funcExists := c.Get("I18n")
	if !funcExists {
		logger.Warning("I18n function not exists in gin context!")
		return ""
	}
	i18nFunc, _ := anyfunc.(func(i18nType locale.I18nType, key string, keyParams ...string) string)
	msg := i18nFunc(locale.Web, name, params...)
	return msg
}
