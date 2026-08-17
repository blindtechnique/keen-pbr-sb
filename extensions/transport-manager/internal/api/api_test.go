package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configpkg "github.com/infaprim/mykeenpbr/internal/config"
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

func TestProcessModeUpdateIsDurableAndExplicitlyRequiresRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := configpkg.Config{
		APIKey:             "secret",
		SingBoxProcessMode: configpkg.SingBoxProcessModeIsolated,
		SingBoxBinary:      "sing-box",
		RuntimeDir:         t.TempDir(),
	}
	if err := configpkg.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	admin := configpkg.NewAdmin(path, cfg, manager, supervisor)
	handler := New(supervisor, "secret", admin)

	request := httptest.NewRequest(
		http.MethodPut,
		"/v1/config/settings",
		strings.NewReader(`{"sing_box_process_mode":"shared"}`),
	)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update settings returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response configpkg.RuntimeSettings
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SingBoxProcessMode != configpkg.SingBoxProcessModeShared ||
		response.RunningSingBoxProcessMode != configpkg.SingBoxProcessModeIsolated ||
		!response.RestartRequired || !response.RuntimeReady {
		t.Fatalf("unsafe or ambiguous mode response: %#v", response)
	}
	stored, err := configpkg.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SingBoxProcessMode != configpkg.SingBoxProcessModeShared {
		t.Fatalf("process mode was not persisted: %#v", stored)
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

func newConditionalAdminHandler(
	t *testing.T,
) (http.Handler, *configpkg.Admin, *transport.Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transports.json")
	cfg := configpkg.Config{
		Listen:        "127.0.0.1:12122",
		APIKey:        "secret",
		SingBoxBinary: "/opt/bin/sing-box",
		RuntimeDir:    filepath.Join(t.TempDir(), "runtime"),
	}
	if err := configpkg.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, revision, err := configpkg.LoadWithRevision(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	admin := configpkg.NewAdminWithRevision(path, loaded, revision, manager, supervisor)
	return New(manager, "secret", admin), admin, manager, path
}

func authenticatedRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	return request
}

func TestTransportConfigStateIsRevisionConsistent(t *testing.T) {
	handler, admin, _, _ := newConditionalAdminHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		authenticatedRequest(http.MethodGet, "/v1/config/transports/state", ""),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("state returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Revision   string                    `json:"revision"`
		Transports []transport.TransportSpec `json:"transports"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Revision != admin.Revision() {
		t.Fatalf("state revision %q does not match admin %q", response.Revision, admin.Revision())
	}
	if recorder.Header().Get("ETag") != `"`+response.Revision+`"` {
		t.Fatalf("unexpected state ETag %q", recorder.Header().Get("ETag"))
	}
	if len(response.Transports) != 0 {
		t.Fatalf("unexpected transports: %#v", response.Transports)
	}
}

func TestConditionalTransportCreateRejectsStaleAndMalformedRevision(t *testing.T) {
	handler, admin, _, _ := newConditionalAdminHandler(t)
	initialRevision := admin.Revision()
	body := `{"tag":"native_one","type":"native","interface":"nwg1"}`

	create := authenticatedRequest(http.MethodPost, "/v1/config/transports", body)
	create.Header.Set("If-Match", initialRevision)
	createRecorder := httptest.NewRecorder()
	handler.ServeHTTP(createRecorder, create)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("conditional create returned %d: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["config_revision"] == "" || created["config_revision"] == initialRevision {
		t.Fatalf("create did not return a new revision: %#v", created)
	}

	stale := authenticatedRequest(
		http.MethodPost,
		"/v1/config/transports",
		`{"tag":"native_two","type":"native","interface":"nwg2"}`,
	)
	stale.Header.Set("If-Match", initialRevision)
	staleRecorder := httptest.NewRecorder()
	handler.ServeHTTP(staleRecorder, stale)
	if staleRecorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale create returned %d: %s", staleRecorder.Code, staleRecorder.Body.String())
	}
	if len(admin.Specs()) != 1 {
		t.Fatalf("stale create mutated config: %#v", admin.Specs())
	}

	malformed := authenticatedRequest(
		http.MethodPost,
		"/v1/config/transports",
		`{"tag":"native_three","type":"native","interface":"nwg3"}`,
	)
	malformed.Header.Set("If-Match", "not-a-revision")
	malformedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(malformedRecorder, malformed)
	if malformedRecorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed revision returned %d: %s", malformedRecorder.Code, malformedRecorder.Body.String())
	}
	if len(admin.Specs()) != 1 {
		t.Fatalf("malformed revision mutated config: %#v", admin.Specs())
	}
}

func TestConditionalTransportUpdateUsesRevision(t *testing.T) {
	handler, admin, _, _ := newConditionalAdminHandler(t)
	if err := admin.Create(
		context.Background(),
		transport.TransportSpec{Tag: "native_one", Type: "native", Interface: "nwg1"},
	); err != nil {
		t.Fatal(err)
	}
	revision := admin.Revision()
	update := authenticatedRequest(
		http.MethodPut,
		"/v1/config/transports/native_one",
		`{"tag":"native_one","display_name":"Дом","type":"native","interface":"nwg1"}`,
	)
	update.Header.Set("If-Match", `"`+revision+`"`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, update)
	if recorder.Code != http.StatusOK {
		t.Fatalf("conditional update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if admin.Specs()[0].DisplayName != "Дом" {
		t.Fatalf("conditional update was not committed: %#v", admin.Specs())
	}

	stale := authenticatedRequest(
		http.MethodPut,
		"/v1/config/transports/native_one",
		`{"tag":"native_one","display_name":"Резерв","type":"native","interface":"nwg1"}`,
	)
	stale.Header.Set("If-Match", revision)
	staleRecorder := httptest.NewRecorder()
	handler.ServeHTTP(staleRecorder, stale)
	if staleRecorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale update returned %d: %s", staleRecorder.Code, staleRecorder.Body.String())
	}
	if admin.Specs()[0].DisplayName != "Дом" {
		t.Fatal("stale update changed transport")
	}
}

func TestTransportValidationHasNoSideEffects(t *testing.T) {
	handler, admin, manager, path := newConditionalAdminHandler(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := admin.Revision()
	request := authenticatedRequest(
		http.MethodPost,
		"/v1/config/transports/validate",
		`{"tag":"native_one","type":"native","interface":"nwg1"}`,
	)
	request.Header.Set("If-Match", revision)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("validation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("validation changed durable transports config")
	}
	if admin.Revision() != revision || len(admin.Specs()) != 0 {
		t.Fatal("validation changed in-memory transport config")
	}
	if _, exists := manager.Get("native_one"); exists {
		t.Fatal("validation registered a runtime transport")
	}
}
