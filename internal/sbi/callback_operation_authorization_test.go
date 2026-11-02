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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nfcontext "github.com/free5gc/nef/internal/context"
	"github.com/free5gc/nef/internal/sbi/consumer"
	"github.com/free5gc/nef/internal/sbi/processor"
	"github.com/free5gc/nef/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallbackOperationAuthorization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer, owner := uuid.NewString(), uuid.NewString()
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
	subjects := map[string]string{"PCF": uuid.NewString(), "SMF": uuid.NewString()}
	var down atomic.Bool
	nrf := interopServer(t, callbackRoleRegistry(t, owner, subjects, &down))
	a := &interopApp{terminationTestApp: terminationTestApp{cfg: &factory.Config{Configuration: &factory.Configuration{
		NfInstanceId: owner, NrfCertPem: path, NrfUri: nrf.URL, Sbi: &factory.Sbi{BindingIPv4: "127.0.0.1"},
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

	// NF roles are known to the issuer fixture; the signed subject is its
	// instance ID, not an invented caller-type claim in the token.

	for _, tc := range []struct {
		name, caller, route string
		authorized          bool
	}{
		{"PCF_to_terminate", "PCF", "terminate", true},
		{"SMF_to_smf", "SMF", "smf", true},
		{"SMF_to_terminate", "SMF", "terminate", false},
		{"PCF_to_smf", "PCF", "smf", false},
		{"unregistered_subject", "PCF", "terminate", false},
		{"missing_subject", "PCF", "terminate", false},
		{"unavailable_NRF", "PCF", "terminate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			down.Store(tc.name == "unavailable_NRF")
			var hits atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				assert.Equal(t, "Bearer outbound-af-token", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusNoContent)
			}))
			defer receiver.Close()
			af := a.ctx.GetOrCreateAf(tc.name)
			corr := a.ctx.NewCorreID()
			af.Mu.Lock()
			sub := af.NewSub(corr, &models.Nef_TrafInfl_TrafficInfluSub{NotificationDestination: receiver.URL})
			sub.AppSessID = "app-" + sub.NotifCorreID
			sub.AppSessURI = "https://pcf.internal/app-sessions/" + sub.AppSessID
			af.Subs[sub.SubID] = sub
			af.Mu.Unlock()
			claims := jwt.MapClaims{
				"iss": issuer, "sub": subjects[tc.caller], "aud": owner, "scope": "nnef-callback",
				"exp": time.Now().Add(time.Minute).Unix(),
			}
			if tc.name == "unregistered_subject" {
				claims["sub"] = uuid.NewString()
			}
			if tc.name == "missing_subject" {
				delete(claims, "sub")
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
			require.NoError(t, err)
			path := "/notification/smf"
			payload := map[string]any{
				"notifId":     sub.NotifCorreID,
				"eventNotifs": []any{map[string]any{"event": "UP_PATH_CH", "timeStamp": "2026-11-02T00:00:00Z"}},
			}
			if tc.route == "terminate" {
				path = "/notification/pcf/" + sub.NotifCorreID + "/terminate"
				payload = map[string]any{"termCause": "PDU_SESSION_TERMINATION", "resUri": sub.AppSessURI}
			}
			data, err := json.Marshal(payload)
			require.NoError(t, err)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				nefServer.URL+factory.NefCallbackResUriPrefix+path, strings.NewReader(string(data)))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := nefServer.Client().Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			af.Mu.RLock()
			_, exists := af.Subs[sub.SubID]
			af.Mu.RUnlock()
			t.Logf("status=%d subscriptionExists=%t afHits=%d", resp.StatusCode, exists, hits.Load())
			if tc.authorized {
				assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			} else {
				if down.Load() {
					assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
				} else {
					assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				}
			}
			assert.Equal(t, !tc.authorized || tc.route != "terminate", exists)
			var want int32
			if tc.authorized && tc.route == "smf" {
				want = 1
			}
			assert.Equal(t, want, hits.Load())
		})
	}
}

// The fixture returns the registered subject's actual role, even when it differs
// from the query, so the consumer must check the returned profile itself.
func callbackRoleRegistry(t *testing.T, owner string, roles map[string]string, down *atomic.Bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			if r.ParseForm() != nil || r.Form.Get("nfInstanceId") != owner {
				http.Error(w, "bad consumer", http.StatusForbidden)
				return
			}
			tok := "outbound-af-token"
			if r.Form.Get("scope") == "nnrf-disc" && r.Form.Get("targetNfType") == "NRF" {
				tok = "discovery-token"
			} else if r.Form.Get("scope") != "nnef-callback" || r.Form.Get("targetNfType") != "AF" {
				http.Error(w, "bad scope", http.StatusForbidden)
				return
			}
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"access_token": tok, "token_type": "Bearer", "expires_in": 60, "scope": r.Form.Get("scope"),
			}))
		case "/nnrf-disc/v1/nf-instances":
			if down != nil && down.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			assert.Equal(t, "Bearer discovery-token", r.Header.Get("Authorization"))
			q := r.URL.Query()
			assert.Equal(t, "NEF", q.Get("requester-nf-type"))
			for role, id := range roles {
				if q.Get("target-nf-instance-id") == id {
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"nfInstances": []any{map[string]any{
						"nfInstanceId": id, "nfType": role, "nfStatus": "REGISTERED",
					}}}))
					return
				}
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"status": 404, "cause": "NF_NOT_FOUND"}))
		default:
			http.NotFound(w, r)
		}
	})
}
