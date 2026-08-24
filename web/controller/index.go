package controller

import (
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/sharif102007/4x-ui/v2/logger"
	"github.com/sharif102007/4x-ui/v2/web/service"
	"github.com/sharif102007/4x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// LoginForm represents the login request structure.
type LoginForm struct {
	Username      string `json:"username" form:"username"`
	Password      string `json:"password" form:"password"`
	TwoFactorCode string `json:"twoFactorCode" form:"twoFactorCode"`
}

// IndexController handles the main index and login-related routes.
type IndexController struct {
	BaseController

	settingService service.SettingService
	userService    service.UserService
	licenseService service.LicenseService
	tgbot          service.Tgbot
}

// NewIndexController creates a new IndexController and initializes its routes.
func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for index, login, logout, and two-factor authentication.
func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	g.GET("/license", a.licensePage)
	g.GET("/logout", a.logout)

	g.POST("/license/activate", a.activateLicense)
	g.POST("/license/refresh", a.refreshLicense)
	g.POST("/login", a.login)
	g.POST("/getTwoFactorEnable", a.getTwoFactorEnable)
}

// index handles the root route, redirecting logged-in users to the panel or showing the login page.
func (a *IndexController) index(c *gin.Context) {
	if !a.licenseService.RuntimeAllowed() {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"license")
		return
	}
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, "panel/")
		return
	}
	html(c, "login.html", "pages.login.title", nil)
}

func (a *IndexController) licensePage(c *gin.Context) {
	html(c, "license.html", "pages.license.title", gin.H{"license": a.licenseService.Status()})
}

func rejectCrossSiteLicensePost(c *gin.Context) bool {
	if c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		c.AbortWithStatus(http.StatusForbidden)
		return true
	}
	return false
}

func (a *IndexController) activateLicense(c *gin.Context) {
	if rejectCrossSiteLicensePost(c) {
		return
	}
	key := c.PostForm("license_key")
	if err := a.licenseService.ActivateLicense(key); err != nil {
		html(c, "license.html", "pages.license.title", gin.H{"license": a.licenseService.Status(), "license_error": err.Error()})
		return
	}
	// Start paid runtimes immediately after successful activation. Each service
	// re-checks the signed local license before doing anything.
	go func() {
		xrayService := service.XrayService{}
		if !xrayService.IsXrayRunning() {
			if err := xrayService.RestartXray(true); err != nil {
				logger.Warning("license: Xray start after activation failed:", err)
			}
		}
		sshService := service.SshManagerService{}
		sshService.RestoreAfterLicense()
	}()
	c.Redirect(http.StatusSeeOther, c.GetString("base_path"))
}

func (a *IndexController) refreshLicense(c *gin.Context) {
	if rejectCrossSiteLicensePost(c) {
		return
	}
	if err := a.licenseService.VerifyLicense(); err != nil {
		html(c, "license.html", "pages.license.title", gin.H{"license": a.licenseService.Status(), "license_error": err.Error()})
		return
	}
	go func() {
		xrayService := service.XrayService{}
		if !xrayService.IsXrayRunning() {
			if err := xrayService.RestartXray(true); err != nil {
				logger.Warning("license: Xray start after verification failed:", err)
			}
		}
		sshService := service.SshManagerService{}
		sshService.RestoreAfterLicense()
	}()
	c.Redirect(http.StatusSeeOther, c.GetString("base_path"))
}

// login handles user authentication and session creation.
func (a *IndexController) login(c *gin.Context) {
	if !a.licenseService.RuntimeAllowed() {
		pureJsonMsg(c, http.StatusForbidden, false, "4x-ui license is not active")
		return
	}
	var form LoginForm

	if err := c.ShouldBind(&form); err != nil {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.invalidFormData"))
		return
	}
	if form.Username == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyUsername"))
		return
	}
	if form.Password == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyPassword"))
		return
	}

	user, checkErr := a.userService.CheckUser(form.Username, form.Password, form.TwoFactorCode)
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	safeUser := template.HTMLEscapeString(form.Username)
	safePass := template.HTMLEscapeString(form.Password)

	if user == nil {
		logger.Warningf("wrong username: \"%s\", password: \"%s\", IP: \"%s\"", safeUser, safePass, getRemoteIp(c))

		notifyPass := safePass

		if checkErr != nil && checkErr.Error() == "invalid 2fa code" {
			translatedError := a.tgbot.I18nBot("tgbot.messages.2faFailed")
			notifyPass = fmt.Sprintf("*** (%s)", translatedError)
		}

		a.tgbot.UserLoginNotify(safeUser, notifyPass, getRemoteIp(c), timeStr, 0)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.wrongUsernameOrPassword"))
		return
	}

	logger.Infof("%s logged in successfully, Ip Address: %s\n", safeUser, getRemoteIp(c))
	a.tgbot.UserLoginNotify(safeUser, ``, getRemoteIp(c), timeStr, 1)

	if err := session.SetLoginUser(c, user); err != nil {
		logger.Warning("Unable to save session:", err)
		return
	}

	logger.Infof("%s logged in successfully", safeUser)
	jsonMsg(c, I18nWeb(c, "pages.login.toasts.successLogin"), nil)
}

// logout handles user logout by clearing the session and redirecting to the login page.
func (a *IndexController) logout(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user != nil {
		logger.Infof("%s logged out successfully", user.Username)
	}
	if err := session.ClearSession(c); err != nil {
		logger.Warning("Unable to clear session on logout:", err)
	}
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
}

// getTwoFactorEnable retrieves the current status of two-factor authentication.
func (a *IndexController) getTwoFactorEnable(c *gin.Context) {
	if !a.licenseService.RuntimeAllowed() {
		pureJsonMsg(c, http.StatusForbidden, false, "4x-ui license is not active")
		return
	}
	status, err := a.settingService.GetTwoFactorEnable()
	if err == nil {
		jsonObj(c, status, nil)
	}
}
