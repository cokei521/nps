package routers

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/servercfg"
	webapi "github.com/djylb/nps/web/api"
	"github.com/djylb/nps/web/framework"
	webservice "github.com/djylb/nps/web/service"
	"github.com/gin-gonic/gin"
)

func sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := framework.EnsureSession(c); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			c.Abort()
			return
		}
		c.Next()
	}
}

func apiInputMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
		if !strings.HasPrefix(contentType, "application/json") || c.Request.Body == nil {
			c.Next()
			return
		}

		payload := make(map[string]interface{})
		decoder := json.NewDecoder(c.Request.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			if err == io.EOF {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, webapi.StatusMessageResponse{
				Status: 0,
				Msg:    "invalid json body",
			})
			return
		}
		for key, value := range payload {
			framework.SetRequestParam(c, key, stringifyAPIValue(value))
		}
		c.Next()
	}
}

func requestContextMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		attachRequestMetadata(c, state.App)
		ensureAutoAdminSession(c, state)
		setActor(c, actorFromSession(c, state.PermissionResolver(), state.AdminUsername()))
		c.Next()
	}
}

func ensureAutoAdminSession(c *gin.Context, state *State) {
	if framework.SessionValue(c, "auth") == true {
		return
	}
	identity, ok := webservice.AutoAdminIdentity(state.CurrentConfig())
	if !ok {
		return
	}
	webapi.ApplySessionIdentity(newAPIContext(c), identity)
	state.System().RegisterManagementAccess(c.ClientIP())
}

func protectedRouteMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := state.CurrentConfig()
		setProtectedRequestData(c, cfg, state.System().Info())

		timestamp, _ := strconv.Atoi(c.Query("timestamp"))
		if !webservice.ValidAuthKey(cfg.Auth.Key, c.Query("auth_key"), timestamp, common.TimeNow().Unix()) {
			if framework.SessionValue(c, "auth") != true {
				abortUnauthorized(c, state.LoginURL())
				return
			}
		} else if err := framework.SetSessionValue(c, "isAdmin", true); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			c.Abort()
			return
		} else {
			setActor(c, webapi.AdminActorWithFallback("", cfg.Web.Username))
		}

		actor := currentActor(c)
		if actor.IsAdmin {
			framework.SetRequestData(c, "isAdmin", true)
			c.Next()
			return
		}

		framework.SetRequestData(c, "client_ids", actor.ClientIDs)
		if clientID, ok := webapi.ActorPrimaryClientID(actor); ok {
			framework.SetRequestData(c, "client_id", clientID)
			framework.SetRequestParam(c, "client_id", strconv.Itoa(clientID))
		}
		framework.SetRequestData(c, "isAdmin", false)
		if actor.Username != "" {
			framework.SetRequestData(c, "username", actor.Username)
		}
		c.Next()
	}
}

func setProtectedRequestData(c *gin.Context, cfg *servercfg.Snapshot, info webservice.SystemInfo) {
	framework.SetRequestData(c, "web_base_url", cfg.Web.BaseURL)
	framework.SetRequestData(c, "head_custom_code", template.HTML(cfg.Web.HeadCustomCode))
	framework.SetRequestData(c, "version", info.Version)
	framework.SetRequestData(c, "year", info.Year)
	framework.SetRequestData(c, "allow_user_login", cfg.Feature.AllowUserLogin)
	framework.SetRequestData(c, "allow_flow_limit", cfg.Feature.AllowFlowLimit)
	framework.SetRequestData(c, "allow_rate_limit", cfg.Feature.AllowRateLimit)
	framework.SetRequestData(c, "allow_time_limit", cfg.Feature.AllowTimeLimit)
	framework.SetRequestData(c, "allow_connection_num_limit", cfg.Feature.AllowConnectionNumLimit)
	framework.SetRequestData(c, "allow_multi_ip", cfg.Feature.AllowMultiIP)
	framework.SetRequestData(c, "system_info_display", cfg.Feature.SystemInfoDisplay)
	framework.SetRequestData(c, "allow_tunnel_num_limit", cfg.Feature.AllowTunnelNumLimit)
	framework.SetRequestData(c, "allow_local_proxy", cfg.Feature.AllowLocalProxy)
	framework.SetRequestData(c, "allow_user_local", cfg.Feature.AllowUserLocal)
	framework.SetRequestData(c, "allow_secret_link", cfg.Feature.AllowSecretLink)
	framework.SetRequestData(c, "allow_user_change_username", cfg.Feature.AllowUserChangeUsername)
}

func permissionMiddleware(state *State, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := state.Authorization().RequirePermission(currentPrincipal(c), permission); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func clientScopeMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolvedClientID, err := state.Authorization().ResolveClient(currentPrincipal(c), requestedClientID(c))
		if err != nil {
			abortAccessError(c, state, err)
			return
		}
		if resolvedClientID > 0 {
			framework.SetRequestData(c, "client_id", resolvedClientID)
			framework.SetRequestParam(c, "client_id", strconv.Itoa(resolvedClientID))
		}
		c.Next()
	}
}

func clientOwnershipMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := requestInt(c, "id")
		if !ok {
			c.Next()
			return
		}
		if err := state.Authorization().RequireClient(currentPrincipal(c), id); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func tunnelOwnershipMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := requestInt(c, "id")
		if !ok {
			c.Next()
			return
		}
		if err := state.Authorization().RequireTunnel(currentPrincipal(c), id); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func hostOwnershipMiddleware(state *State) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := requestInt(c, "id")
		if !ok {
			c.Next()
			return
		}
		if err := state.Authorization().RequireHost(currentPrincipal(c), id); err != nil {
			abortAccessError(c, state, err)
			return
		}
		c.Next()
	}
}

func requestInt(c *gin.Context, key string) (int, bool) {
	if raw, ok := framework.RequestParam(c, key); ok && raw != "" {
		value, err := strconv.Atoi(raw)
		if err == nil {
			return value, true
		}
		return 0, false
	}
	raw := c.Request.FormValue(key)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return value, true
}

func requestedClientID(c *gin.Context) int {
	raw := strings.TrimSpace(c.Request.FormValue("client_id"))
	if raw == "" {
		if requestValue, ok := framework.RequestParam(c, "client_id"); ok {
			raw = strings.TrimSpace(requestValue)
		}
	}
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return value
}

func stringifyAPIValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case json.Number:
		return v.String()
	case []interface{}, map[string]interface{}:
		if data, err := json.Marshal(v); err == nil {
			return string(data)
		}
	}
	if data, err := json.Marshal(value); err == nil {
		text := string(data)
		if text != "null" {
			return text
		}
	}
	return ""
}

func abortUnauthorized(c *gin.Context, loginURL string) {
	if isMachineAPIRequest(c) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, webapi.StatusMessageResponse{
			Status: 0,
			Msg:    "unauthorized",
		})
		return
	}
	c.Redirect(http.StatusFound, loginURL)
	c.Abort()
}

func abortForbidden(c *gin.Context) {
	if isMachineAPIRequest(c) {
		c.AbortWithStatusJSON(http.StatusForbidden, webapi.StatusMessageResponse{
			Status: 0,
			Msg:    "forbidden",
		})
		return
	}
	c.AbortWithStatus(http.StatusForbidden)
}

func abortAccessError(c *gin.Context, state *State, err error) {
	loginURL := "/login/index"
	if state != nil {
		loginURL = state.LoginURL()
	}
	switch {
	case errors.Is(err, webservice.ErrUnauthenticated):
		abortUnauthorized(c, loginURL)
	case errors.Is(err, webservice.ErrForbidden):
		abortForbidden(c)
	default:
		abortForbidden(c)
	}
}

func isMachineAPIRequest(c *gin.Context) bool {
	path := c.Request.URL.Path
	return strings.Contains(path, "/api/v1/")
}

func currentPrincipal(c *gin.Context) webservice.Principal {
	return webapi.PrincipalFromActor(currentActor(c))
}
