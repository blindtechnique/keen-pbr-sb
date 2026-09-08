package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	configpkg "github.com/infaprim/mykeenpbr/internal/config"
	"github.com/infaprim/mykeenpbr/internal/transport"
)

type geoAdminStub struct {
	recordingAdminStub
	calls   int
	request configpkg.NativeGeoUpdate
}

func (g *geoAdminStub) UpdateNativeGeo(_ context.Context, request configpkg.NativeGeoUpdate) (bool, string, error) {
	g.calls++
	g.request = request
	return false, strings.Repeat("a", 64), nil
}

func TestNativeGeoEndpointIsNarrowAuthenticatedAndAllowsStaleNoop(t *testing.T) {
	admin := &geoAdminStub{}
	handler := New(transport.NewManager(), "secret", admin)
	body := `{"tag":"native_one","expected_interface":"nwg5","country_code":"DE","country":"Germany"}`
	for _, test := range []struct {
		name, body string
		auth       bool
		status     int
	}{
		{"unauthorized", body, false, http.StatusUnauthorized},
		{"stale no-op", body, true, http.StatusOK},
		{"no full spec", strings.TrimSuffix(body, "}") + `,"display_name":"old name"}`, true, http.StatusBadRequest},
		{"no mode replay", strings.TrimSuffix(body, "}") + `,"geo_mode":"auto"}`, true, http.StatusBadRequest},
		{"trailing JSON", body + `{}`, true, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/config/transports/geo", strings.NewReader(test.body))
			if test.auth {
				request.Header.Set("Authorization", "Bearer secret")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body.String())
			}
			if test.status == http.StatusOK && !strings.Contains(response.Body.String(), `"updated":false`) {
				t.Fatal("stale result must be an ordinary no-op")
			}
		})
	}
	if admin.calls != 1 || admin.request.ExpectedInterface != "nwg5" {
		t.Fatal("invalid requests reached metadata writer")
	}
}
