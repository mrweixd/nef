package sbi

import (
	"net/http"

	"github.com/free5gc/nef/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/metrics/sbi"
	"github.com/gin-gonic/gin"
)

func (s *Server) getCallbackRoutes() []Route {
	return []Route{
		{Method: http.MethodPost, Pattern: "/notification/pcf/:correlationID/terminate", APIFunc: s.apiPcfTermination},
		{
			Method:  http.MethodPost,
			Pattern: "/notification/smf",
			APIFunc: s.apiPostSmfNotification,
		},
	}
}

func (s *Server) apiPostSmfNotification(gc *gin.Context) {
	var eeNotif models.Smf_EvtExpos_NsmfEventExposureNotification
	reqBody, err := gc.GetRawData()
	if err != nil {
		logger.SBILog.Errorf("Get Request Body error: %+v", err)
		pd := openapi.ProblemDetailsSystemFailure(err.Error())
		gc.Set(sbi.IN_PB_DETAILS_CTX_STR, pd.Cause)
		gc.JSON(http.StatusInternalServerError, pd)
		return
	}

	err = openapi.Deserialize(&eeNotif, reqBody, "application/json")
	if err != nil {
		logger.SBILog.Errorf("Deserialize Request Body error: %+v", err)
		pd := openapi.ProblemDetailsMalformedReqSyntax(err.Error())
		gc.Set(sbi.IN_PB_DETAILS_CTX_STR, pd.Cause)
		gc.JSON(http.StatusBadRequest, pd)
		return
	}

	if !s.authorizeCallbackOperation(gc, models.Nrf_NFMgmt_NFType_SMF) {
		return
	}
	s.Processor().SmfNotification(gc, &eeNotif)
}

func (s *Server) apiPcfTermination(c *gin.Context) {
	var info models.Pcf_PolAuth_TerminationInfo
	if err := c.ShouldBindJSON(&info); err != nil || info.ResUri == "" || info.TermCause == "" {
		pd := openapi.ProblemDetailsMalformedReqSyntax("Invalid termination notification")
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, pd.Cause)
		c.JSON(http.StatusBadRequest, pd)
		return
	}
	if !s.authorizeCallbackOperation(c, models.Nrf_NFMgmt_NFType_PCF) {
		return
	}
	s.Processor().PcfTermination(c, c.Param("correlationID"), info.ResUri)
}
