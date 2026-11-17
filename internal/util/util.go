package util

import (
	nef_context "github.com/free5gc/nef/internal/context"
	"github.com/free5gc/nef/internal/logger"
	"github.com/free5gc/nef/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
)

// Metrics consts
const (
	METRICS_APP_PFDS_CREATION_ERR_MSG = "PFDs for all application were not created successfully"
)

type RouterAuthorizationCheck struct {
	serviceName models.Nrf_NFMgmt_ServiceName
}

func NewRouterAuthorizationCheck(serviceName models.Nrf_NFMgmt_ServiceName) *RouterAuthorizationCheck {
	return &RouterAuthorizationCheck{
		serviceName: serviceName,
	}
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, nefCtx nef_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	if err := nefCtx.AuthorizationCheck(token, rac.serviceName); err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Unauthorized: %s", err.Error())
		baseURI := "http://localhost"
		if withConfig, ok := nefCtx.(interface{ Config() *factory.Config }); ok {
			if cfg := withConfig.Config(); cfg != nil {
				baseURI = cfg.SbiUri()
			}
		}
		status, challenge, reason := oauthChallenge(c.Request, string(rac.serviceName), token, err, baseURI)
		c.Header("WWW-Authenticate", challenge)
		c.JSON(status, gin.H{"error": reason})
		c.Abort()
		return
	}
	logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Authorized")
}
