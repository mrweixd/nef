package sbi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nfcontext "github.com/free5gc/nef/internal/context"
	"github.com/free5gc/nef/internal/sbi/consumer"
	"github.com/free5gc/nef/internal/sbi/notifier"
	"github.com/free5gc/nef/internal/sbi/processor"
	"github.com/free5gc/nef/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type interopApp struct {
	terminationTestApp
	proc *processor.Processor
	cons *consumer.Consumer
}

func (a *interopApp) Processor() *processor.Processor { return a.proc }
func (a *interopApp) Consumer() *consumer.Consumer    { return a.cons }
func (*interopApp) Notifier() *notifier.Notifier      { return nil }

func interopServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.Config.Protocols = new(http.Protocols)
	s.Config.Protocols.SetHTTP1(true)
	s.Config.Protocols.SetUnencryptedHTTP2(true)
	s.Start()
	t.Cleanup(s.Close)
	return s
}

// With PCF_INTEROP_TEST_BIN set, send the success case from the actual PCF processor.
func TestPCFTerminationInterop(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer, owner, caller := uuid.NewString(), uuid.NewString(), uuid.NewString()
	san, err := url.Parse("urn:uuid:" + issuer)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{san}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "nrf.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	roleNRF := interopServer(t, callbackRoleRegistry(t, owner, map[string]string{"PCF": caller}, nil))
	a := &interopApp{terminationTestApp: terminationTestApp{cfg: &factory.Config{Configuration: &factory.Configuration{
		NfInstanceId: owner, NrfCertPem: path, NrfUri: roleNRF.URL, Sbi: &factory.Sbi{BindingIPv4: "127.0.0.1"},
	}}}}
	a.ctx, err = nfcontext.NewContext(a)
	require.NoError(t, err)
	require.NoError(t, a.ctx.SetOAuth2Required(true))
	a.cons, err = consumer.NewConsumer(a)
	require.NoError(t, err)
	a.proc, err = processor.NewProcessor(a)
	require.NoError(t, err)
	s, err := NewServer(a, "")
	require.NoError(t, err)
	nefServer := interopServer(t, s.router)
	af := a.ctx.GetOrCreateAf("af")
	sub := af.NewSub(a.ctx.NewCorreID(), &models.Nef_TrafInfl_TrafficInfluSub{})
	sub.AppSessID = "imsi-test-1"
	sub.AppSessURI = "https://pcf.internal/app-sessions/" + sub.AppSessID
	af.Subs[sub.SubID] = sub
	callback := nefServer.URL + factory.NefCallbackResUriPrefix + "/notification/pcf/" + sub.NotifCorreID
	sign := func(scope, aud string) (string, error) {
		return jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"iss": issuer, "sub": caller, "aud": aud, "scope": scope, "exp": time.Now().Add(time.Minute).Unix(),
		}).SignedString(key)
	}
	post := func(scope, aud string) int {
		token, e := sign(scope, aud)
		require.NoError(t, e)
		body := "{\"termCause\":\"PDU_SESSION_TERMINATION\",\"resUri\":\"" + sub.AppSessURI + "\"}"
		req, e := http.NewRequestWithContext(t.Context(), http.MethodPost, callback+"/terminate", strings.NewReader(body))
		require.NoError(t, e)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, e := nefServer.Client().Do(req)
		require.NoError(t, e)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode
	}
	allowed, ok := nfcontext.AllowedNfTypesForService(nfcontext.ServiceNameNnefCallback)
	require.True(t, ok)
	require.Contains(t, allowed, models.Nrf_NFMgmt_NFType_PCF)
	require.Contains(t, allowed, models.Nrf_NFMgmt_NFType_SMF)
	require.NotContains(t, allowed, models.Nrf_NFMgmt_NFType_AF)
	require.Equal(t, http.StatusUnauthorized, post("npcf-policyauthorization", owner))
	require.Equal(t, http.StatusUnauthorized, post("nnef-callback", uuid.NewString()))
	bin := os.Getenv("PCF_INTEROP_TEST_BIN")
	if bin == "" {
		require.Equal(t, http.StatusNoContent, post("nnef-callback", owner))
	} else {
		nrf := interopServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/nnrf-disc/v1/nf-instances":
				assert.Equal(t, "NEF", r.URL.Query().Get("target-nf-type"))
				assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"nfInstances": []any{map[string]any{
					"nfInstanceId": owner,
					"nfType":       "NEF", "nfStatus": "REGISTERED",
					"nfServices": []any{map[string]any{
						"serviceName": "nnef-callback", "nfServiceStatus": "REGISTERED", "apiPrefix": nefServer.URL,
					}},
				}}}))
			case "/oauth2/token":
				assert.NoError(t, r.ParseForm())
				scope := r.Form.Get("scope")
				aud := r.Form.Get("targetNfInstanceId")
				valid := r.Form.Get("nfInstanceId") == caller && r.Form.Get("nfType") == "PCF"
				if scope == "nnef-callback" {
					valid = valid && slices.Contains(allowed, models.Nrf_NFMgmt_NFType_PCF) &&
						aud == owner && r.Form.Get("targetNfType") == "NEF"
				} else {
					valid = valid && scope == "nnrf-disc" && aud == issuer && r.Form.Get("targetNfType") == "NRF"
				}
				if !valid {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				tok, e := sign(scope, aud)
				assert.NoError(t, e)
				assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
					"access_token": tok, "token_type": "Bearer", "expires_in": 60, "scope": scope,
				}))
			default:
				http.NotFound(w, r)
			}
		}))
		cmd := exec.CommandContext(t.Context(), bin, "-test.run=^TestPCFTerminationInteropClient$", "-test.v")
		cmd.Env = append(os.Environ(), "INTEROP_PCF_ID="+caller, "INTEROP_NRF_ID="+issuer,
			"INTEROP_NRF="+nrf.URL, "INTEROP_CALLBACK="+callback, "INTEROP_RESOURCE="+sub.AppSessURI)
		out, e := cmd.CombinedOutput()
		require.NoError(t, e, string(out))
		t.Log(string(out))
	}
	af.Mu.RLock()
	defer af.Mu.RUnlock()
	require.NotContains(t, af.Subs, sub.SubID)
}
