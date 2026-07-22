package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type exportAdminStub struct {
	specs []transport.TransportSpec
}

func (s exportAdminStub) Specs() []transport.TransportSpec                    { return s.specs }
func (s exportAdminStub) ExportSpecs() []transport.TransportSpec              { return s.specs }
func (exportAdminStub) Create(context.Context, transport.TransportSpec) error { return nil }
func (exportAdminStub) Update(context.Context, string, transport.TransportSpec) error {
	return nil
}
func (exportAdminStub) Delete(context.Context, string) error { return nil }

func TestHealthDoesNotRequireAuthentication(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	New(transport.NewManager(), "secret").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestTransportListRequiresAuthentication(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/transports", nil)
	New(transport.NewManager(), "secret").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestTransportListWithAuthentication(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/transports", nil)
	request.Header.Set("Authorization", "Bearer secret")
	New(transport.NewManager(), "secret").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestUnknownTransportReturnsNotFound(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/transports/missing", nil)
	request.Header.Set("Authorization", "Bearer secret")
	New(transport.NewManager(), "secret").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestTransportExportRequiresAuthenticationAndIncludesSecrets(t *testing.T) {
	admin := exportAdminStub{specs: []transport.TransportSpec{{
		Tag: "proxy_one", Type: "sing-box", Interface: "proxy1", Link: "vless://secret",
	}}}
	handler := New(transport.NewManager(), "secret", admin)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(
		unauthorized,
		httptest.NewRequest(http.MethodGet, "/v1/config/transports/export", nil),
	)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized export returned status %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/config/transports/export", nil)
	request.Header.Set("Authorization", "Bearer secret")
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized export returned status %d", authorized.Code)
	}
	if authorized.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export cache policy is %q", authorized.Header().Get("Cache-Control"))
	}
	if !strings.Contains(authorized.Body.String(), "vless://secret") {
		t.Fatalf("export omitted connection data: %s", authorized.Body.String())
	}
}
