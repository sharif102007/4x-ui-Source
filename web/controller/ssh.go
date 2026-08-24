package controller

import (
	"strconv"

	"github.com/sharif102007/4x-ui/v2/database/model"
	"github.com/sharif102007/4x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// SshController exposes the SSH Manager REST API under /panel/api/ssh/.
// Routes match the frontend expected URLs exactly.
type SshController struct {
	sshService service.SshManagerService
}

func NewSshController(g *gin.RouterGroup) *SshController {
	a := &SshController{}
	a.initRouter(g)
	return a
}

func (a *SshController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/ssh")

	g.GET("/inbounds", a.listInbounds)
	g.POST("/inbounds/add", a.addInbound)
	g.POST("/inbounds/update/:id", a.updateInbound)
	g.POST("/inbounds/enable/:id", a.enableInbound)
	g.POST("/inbounds/disable/:id", a.disableInbound)
	g.POST("/inbounds/del/:id", a.delInbound)
	g.POST("/inbounds/checkPort", a.checkPort)

	g.GET("/users", a.listUsers)
	g.POST("/users/add", a.addUser)
	g.POST("/users/update/:id", a.updateUser)
	g.POST("/users/enable/:id", a.enableUser)
	g.POST("/users/disable/:id", a.disableUser)
	g.POST("/users/del/:id", a.delUser)
	g.POST("/users/resetTraffic/:id", a.resetUserTraffic)
}

func (a *SshController) listInbounds(c *gin.Context) {
	list, err := a.sshService.GetInbounds()
	if err != nil {
		jsonMsg(c, "Failed to load SSH inbounds", err)
		return
	}
	jsonObj(c, list, nil)
}

func (a *SshController) addInbound(c *gin.Context) {
	in := &model.SshInbound{}
	if err := c.ShouldBind(in); err != nil {
		jsonMsg(c, "Invalid request", err)
		return
	}
	out, err := a.sshService.AddInbound(in)
	if err != nil {
		jsonMsg(c, "Failed to create SSH inbound", err)
		return
	}
	jsonMsgObj(c, "SSH inbound created", out, nil)
}

func (a *SshController) updateInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	in := &model.SshInbound{Id: id}
	if err := c.ShouldBind(in); err != nil {
		jsonMsg(c, "Invalid request", err)
		return
	}
	in.Id = id
	out, err := a.sshService.UpdateInbound(in)
	if err != nil {
		jsonMsg(c, "Failed to update SSH inbound", err)
		return
	}
	jsonMsgObj(c, "SSH inbound updated", out, nil)
}

func (a *SshController) enableInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.SetInboundEnable(id, true); err != nil {
		jsonMsg(c, "Failed to enable SSH inbound", err)
		return
	}
	jsonMsg(c, "SSH inbound enabled", nil)
}

func (a *SshController) disableInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.SetInboundEnable(id, false); err != nil {
		jsonMsg(c, "Failed to disable SSH inbound", err)
		return
	}
	jsonMsg(c, "SSH inbound disabled", nil)
}

func (a *SshController) delInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.DelInbound(id); err != nil {
		jsonMsg(c, "Failed to delete SSH inbound", err)
		return
	}
	jsonMsg(c, "SSH inbound deleted", nil)
}

func (a *SshController) checkPort(c *gin.Context) {
	type req struct {
		Port    int `json:"port" form:"port"`
		Exclude int `json:"exclude" form:"exclude"`
	}
	var r req
	if err := c.ShouldBind(&r); err != nil {
		jsonMsg(c, "Invalid request", err)
		return
	}
	if err := a.sshService.CheckPortConflict(r.Port, r.Exclude); err != nil {
		jsonMsg(c, "Port conflict", err)
		return
	}
	jsonMsg(c, "Port is available", nil)
}

func (a *SshController) listUsers(c *gin.Context) {
	list, err := a.sshService.GetUsers()
	if err != nil {
		jsonMsg(c, "Failed to load SSH users", err)
		return
	}
	jsonObj(c, list, nil)
}

func (a *SshController) addUser(c *gin.Context) {
	u := &model.SshUser{}
	if err := c.ShouldBind(u); err != nil {
		jsonMsg(c, "Invalid request", err)
		return
	}
	if err := a.sshService.AddUser(u); err != nil {
		jsonMsg(c, "Failed to create SSH user", err)
		return
	}
	jsonMsgObj(c, "SSH user created", u, nil)
}

func (a *SshController) updateUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	u := &model.SshUser{Id: id}
	if err := c.ShouldBind(u); err != nil {
		jsonMsg(c, "Invalid request", err)
		return
	}
	u.Id = id
	if err := a.sshService.UpdateUser(u); err != nil {
		jsonMsg(c, "Failed to update SSH user", err)
		return
	}
	jsonMsg(c, "SSH user updated", nil)
}

func (a *SshController) enableUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.SetUserEnable(id, true); err != nil {
		jsonMsg(c, "Failed to enable SSH user", err)
		return
	}
	jsonMsg(c, "SSH user enabled", nil)
}

func (a *SshController) disableUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.SetUserEnable(id, false); err != nil {
		jsonMsg(c, "Failed to disable SSH user", err)
		return
	}
	jsonMsg(c, "SSH user disabled", nil)
}

func (a *SshController) delUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.DelUser(id); err != nil {
		jsonMsg(c, "Failed to delete SSH user", err)
		return
	}
	jsonMsg(c, "SSH user deleted", nil)
}

func (a *SshController) resetUserTraffic(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid id", err)
		return
	}
	if err := a.sshService.ResetUserTraffic(id); err != nil {
		jsonMsg(c, "Failed to reset traffic", err)
		return
	}
	jsonMsg(c, "SSH user traffic reset", nil)
}
