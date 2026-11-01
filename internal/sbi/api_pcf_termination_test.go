package sbi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nfcontext "github.com/free5gc/nef/internal/context"
	"github.com/free5gc/nef/pkg/factory"
	"github.com/stretchr/testify/require"
)

type terminationTestApp struct {
	nef
	cfg *factory.Config
	ctx *nfcontext.NefContext
}

func (a *terminationTestApp) Config() *factory.Config        { return a.cfg }
func (a *terminationTestApp) Context() *nfcontext.NefContext { return a.ctx }

func TestPcfTerminationRoute(t *testing.T) {
	app := &terminationTestApp{cfg: &factory.Config{Configuration: &factory.Configuration{
		Sbi: &factory.Sbi{BindingIPv4: "127.0.0.1"},
	}}}
	var err error
	app.ctx, err = nfcontext.NewContext(app)
	require.NoError(t, err)
	server, err := NewServer(app, "")
	require.NoError(t, err)
	for _, required := range []bool{true, false} {
		app.ctx.OAuth2Required = required
		path := factory.NefCallbackResUriPrefix + "/notification/pcf/1/terminate"
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path,
			strings.NewReader("{}"))
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		if required {
			require.Equal(t, http.StatusUnauthorized, w.Code)
		} else {
			require.Equal(t, http.StatusBadRequest, w.Code)
		}
	}
}
