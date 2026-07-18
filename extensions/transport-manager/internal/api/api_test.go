package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

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
