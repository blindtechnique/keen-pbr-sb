package config

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

func TestUpgradeStateCapturesAuthenticatedIntentWithoutChangingAutoStart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/transports" || r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("capture did not use the existing authenticated read endpoint")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `[{"tag":"stopped","desired_up":false},{"tag":"started","desired_up":true}]`)
	}))
	defer server.Close()
	cfg := Config{Listen: strings.TrimPrefix(server.URL, "http://"), APIKey: "test-secret",
		Transports: []transport.TransportSpec{
			{Tag: "stopped", Type: "sing-box", AutoStart: true},
			{Tag: "started", Type: "sing-box", AutoStart: false},
		}}
	configPath := filepath.Join(t.TempDir(), "transports.json")
	if err := Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(configPath)
	statePath := filepath.Join(t.TempDir(), "upgrade.json")
	if err := CaptureUpgradeState(context.Background(), cfg, configRevision(before), statePath); err != nil {
		t.Fatal(err)
	}
	desired, err := ReadUpgradeState(statePath, configRevision(before))
	if err != nil || !reflect.DeepEqual(desired, map[string]bool{"stopped": false, "started": true}) {
		t.Fatalf("wrong upgrade intent: %v, %v", desired, err)
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(before) || !cfg.Transports[0].AutoStart || cfg.Transports[1].AutoStart {
		t.Fatal("capture rewrote auto_start or persistent config")
	}
	encoded, _ := os.ReadFile(statePath)
	if strings.Contains(string(encoded), "test-secret") {
		t.Fatal("handoff contains credentials")
	}
	if _, err := ReadUpgradeState(statePath, "another-config"); err == nil {
		t.Fatal("accepted a handoff from another configuration")
	}
	if state, err := ReadUpgradeState("", "another-config"); err != nil || state != nil {
		t.Fatal("ordinary startup did not retain auto_start semantics")
	}
}

func TestUpgradeStateFailureDoesNotPublishOrMutateServices(t *testing.T) {
	for _, response := range []struct {
		name, body string
		status     int
	}{
		{"unavailable", `{"error":"not ready"}`, http.StatusServiceUnavailable},
		{"unauthenticated", `{"error":"unauthorized"}`, http.StatusUnauthorized},
		{"malformed", `{`, http.StatusOK},
		{"missing_desired", `[{"tag":"proxy"}]`, http.StatusOK},
		{"missing_transport", `[]`, http.StatusOK},
		{"duplicate", `[{"tag":"proxy","desired_up":false},{"tag":"proxy","desired_up":true}]`, http.StatusOK},
		{"trailing", `[{"tag":"proxy","desired_up":false}] {}`, http.StatusOK},
	} {
		t.Run(response.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("capture attempted a mutation")
				}
				w.WriteHeader(response.status)
				fmt.Fprint(w, response.body)
			}))
			defer server.Close()
			cfg := Config{Listen: strings.TrimPrefix(server.URL, "http://"), APIKey: "test-secret",
				Transports: []transport.TransportSpec{{Tag: "proxy", Type: "sing-box", AutoStart: true}}}
			path := filepath.Join(t.TempDir(), "upgrade.json")
			if err := CaptureUpgradeState(context.Background(), cfg, "revision", path); err == nil {
				t.Fatal("invalid capture succeeded")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("failed capture published a handoff")
			}
		})
	}
}

func TestExplicitUpgradeStateDoesNotFallBackAfterInvalidHandoff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.json")
	for _, data := range []string{
		`{`,
		`{"config_revision":"revision"}`,
		`{"config_revision":"revision","desired_up":{"proxy":"false"}}`,
		`{"config_revision":"revision","desired_up":{"proxy":false}} {}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadUpgradeState(path, "revision"); err == nil {
			t.Fatalf("invalid explicit handoff silently used auto_start: %s", data)
		}
	}
}
