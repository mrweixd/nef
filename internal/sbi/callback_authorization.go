package sbi

import (
	"net/http"
	"strings"

	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const callbackSubjectKey = "nef.verifiedCallbackSubject"

// Only called on the token accepted by the callback group's OAuth middleware.
func verifiedCallbackSubject(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	var claims jwt.RegisteredClaims
	_, _, err := jwt.NewParser().ParseUnverified(fields[1], &claims)
	if err != nil {
		return "", false
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil || id == uuid.Nil || id.String() != claims.Subject {
		return "", false
	}
	return claims.Subject, true
}

func (s *Server) authorizeCallbackOperation(c *gin.Context, required models.Nrf_NFMgmt_NFType) bool {
	if !s.Context().OAuth2Required {
		return true
	}
	subject := c.GetString(callbackSubjectKey)
	if subject != "" {
		ok, err := s.Processor().Consumer().RegisteredCallbackCaller(subject, required)
		if err != nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return false
		}
		if ok {
			return true
		}
	}
	c.AbortWithStatus(http.StatusForbidden)
	return false
}
