package api

import (
	"context"
	"encoding/json"
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

type recordingAdminStub struct {
	specs []transport.TransportSpec
}

type revisionAdminStub struct {
	*recordingAdminStub
	revision string
}

func (s revisionAdminStub) Revision() string {
	return s.revision
}

func (s *recordingAdminStub) Specs() []transport.TransportSpec {
	return append([]transport.TransportSpec(nil), s.specs...)
}

func (s *recordingAdminStub) Create(_ context.Context, spec transport.TransportSpec) error {
	s.specs = append(s.specs, spec)
	return nil
}

func (s *recordingAdminStub) Update(
	_ context.Context,
	tag string,
	spec transport.TransportSpec,
) error {
	for index := range s.specs {
		if s.specs[index].Tag == tag {
			s.specs[index] = spec
			return nil
		}
	}
	s.specs = append(s.specs, spec)
	return nil
}

func (s *recordingAdminStub) Delete(_ context.Context, tag string) error {
	for index := range s.specs {
		if s.specs[index].Tag == tag {
			s.specs = append(s.specs[:index], s.specs[index+1:]...)
			break
		}
	}
	return nil
}

func TestHealthDoesNotRequireAuthentication(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	New(transport.NewManager(), "secret").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
}

func TestHealthReportsLoadedConfigRevision(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	admin := revisionAdminStub{
		recordingAdminStub: &recordingAdminStub{},
		revision:           strings.Repeat("a", 64),
	}
	New(transport.NewManager(), "secret", admin).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["config_revision"] != admin.revision {
		t.Fatalf("unexpected config revision: %#v", response)
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

func TestTransportDisplayNameRoundTripsThroughHTTP(t *testing.T) {
	admin := &recordingAdminStub{}
	handler := New(transport.NewManager(), "secret", admin)
	create := httptest.NewRequest(
		http.MethodPost,
		"/v1/config/transports",
		strings.NewReader(`{
			"tag":"tr_example",
			"display_name":"Рабочий VLESS",
			"type":"sing-box",
			"interface":"kpbr12345678",
			"link":"vless://example"
		}`),
	)
	create.Header.Set("Authorization", "Bearer secret")
	createRecorder := httptest.NewRecorder()
	handler.ServeHTTP(createRecorder, create)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", createRecorder.Code, createRecorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/v1/config/transports", nil)
	list.Header.Set("Authorization", "Bearer secret")
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
	var specs []transport.TransportSpec
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &specs); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(specs) != 1 || specs[0].DisplayName != "Рабочий VLESS" {
		t.Fatalf("display name did not round-trip: %#v", specs)
	}

	update := httptest.NewRequest(
		http.MethodPut,
		"/v1/config/transports/tr_example",
		strings.NewReader(`{
			"tag":"tr_example",
			"display_name":"Резервный VLESS",
			"type":"sing-box",
			"interface":"kpbr12345678",
			"link":"vless://example"
		}`),
	)
	update.Header.Set("Authorization", "Bearer secret")
	updateRecorder := httptest.NewRecorder()
	handler.ServeHTTP(updateRecorder, update)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", updateRecorder.Code, updateRecorder.Body.String())
	}
	if got := admin.Specs()[0].DisplayName; got != "Резервный VLESS" {
		t.Fatalf("updated display name is %q", got)
	}
}

func TestTransportDisplayNameHTTPValidationUsesUnicodeCodePoints(t *testing.T) {
	handler := New(transport.NewManager(), "secret", &recordingAdminStub{})
	for name, displayName := range map[string]string{
		"more than eighty code points": strings.Repeat("🚀", 81),
		"bidirectional control":        "safe\u202etxt.exe",
	} {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(transport.TransportSpec{
				Tag:         "tr_example",
				DisplayName: displayName,
				Type:        "sing-box",
				Interface:   "kpbr12345678",
				Link:        "vless://example",
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/config/transports",
				strings.NewReader(string(body)),
			)
			request.Header.Set("Authorization", "Bearer secret")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}

	validBody, err := json.Marshal(transport.TransportSpec{
		Tag:         "tr_valid",
		DisplayName: strings.Repeat("🚀", 80),
		Type:        "sing-box",
		Interface:   "kpbr12345678",
		Link:        "vless://example",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/config/transports",
		strings.NewReader(string(validBody)),
	)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTransportConfigRejectsUnknownFieldsAndMultipleValues(t *testing.T) {
	handler := New(transport.NewManager(), "secret", &recordingAdminStub{})
	for name, body := range map[string]string{
		"unknown field": `{
			"tag":"tr_example",
			"display_name":"VLESS",
			"type":"sing-box",
			"interface":"kpbr12345678",
			"unknown_alias":"lost"
		}`,
		"multiple values": `{"tag":"tr_example","type":"sing-box","interface":"kpbr12345678"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/config/transports",
				strings.NewReader(body),
			)
			request.Header.Set("Authorization", "Bearer secret")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
