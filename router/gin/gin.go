package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	basicauth "github.com/pucora/pucora-basicauth/v2"
	"github.com/pucora/lura/v2/config"
	"github.com/pucora/lura/v2/logging"
	"github.com/pucora/lura/v2/proxy"
	ginlura "github.com/pucora/lura/v2/router/gin"
)

// Service holds service-level basic auth configuration.
type Service struct {
	Config      basicauth.Config
	Credentials basicauth.Credentials
}

// NewService loads service-level credentials.
func NewService(cfg config.ServiceConfig, logger logging.Logger) *Service {
	svcCfg, ok := basicauth.ParseConfig(cfg.ExtraConfig)
	if !ok {
		return &Service{}
	}
	creds, err := basicauth.LoadCredentials(svcCfg)
	if err != nil {
		logger.Error("[SERVICE: BasicAuth]", "Unable to load credentials:", err.Error())
		return &Service{Config: svcCfg}
	}
	return &Service{Config: svcCfg, Credentials: creds}
}

// HandlerFactory protects endpoints configured with auth/basic.
func HandlerFactory(hf ginlura.HandlerFactory, logger logging.Logger, service *Service) ginlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		epCfg, enabled := basicauth.MergeConfig(service.Config, cfg.ExtraConfig)
		if !enabled {
			return hf(cfg, p)
		}
		creds := service.Credentials
		if epCfg.HtpasswdPath != "" || len(epCfg.Users) > 0 {
			loaded, err := basicauth.LoadCredentials(epCfg)
			if err != nil {
				logger.Error("[ENDPOINT: "+cfg.Endpoint+"][BasicAuth]", err.Error())
				return func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) }
			}
			creds = loaded
		}
		if len(creds) == 0 {
			logger.Warning("[ENDPOINT: "+cfg.Endpoint+"][BasicAuth]", "No credentials configured")
			return hf(cfg, p)
		}
		next := hf(cfg, p)
		return func(c *gin.Context) {
			user, pass, ok := c.Request.BasicAuth()
			if !ok || !creds.Validate(user, pass) {
				c.Header("WWW-Authenticate", `Basic realm="pucora"`)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			next(c)
		}
	}
}
