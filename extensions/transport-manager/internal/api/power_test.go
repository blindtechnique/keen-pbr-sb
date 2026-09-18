package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type powerAdminStub struct {
	exportAdminStub
	calls   int
	tag     string
	enabled bool
	err     error
}

func (s *powerAdminStub) SetEnabled(_ context.Context, tag string, enabled bool) error {
	s.calls++
	s.tag, s.enabled = tag, enabled
	return s.err
}

func TestPanelPowerUsesDurableAdminOnlyWhenExplicitlyRequested(t *testing.T) {
	for _, test := range []struct {
		name, action                     string
		persistent, temporary, auth      bool
		status, adminCalls, runtimeCalls int
	}{
		{"panel_on", "up", true, false, true, 202, 1, 0},
		{"panel_off", "down", true, false, true, 202, 1, 0},
		{"internal_resume", "up", false, false, true, 202, 0, 1},
		{"internal_stop", "down", false, false, true, 202, 0, 1},
		{"restart", "restart", false, false, true, 202, 0, 1},
		{"persistent_restart_invalid", "restart", true, false, true, 400, 0, 0},
		{"temporary_is_not_persistent", "down", true, true, true, 400, 0, 0},
		{"authentication_required", "down", true, false, false, 401, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtimeCalls := 0
			runtime := &shutdownRuntimeStub{operation: func(context.Context) error { runtimeCalls++; return nil }}
			admin := &powerAdminStub{}
			handler := New(runtime, "test-key", admin)
			request := httptest.NewRequest(http.MethodPost, "/v1/transports/proxy/"+test.action, nil)
			if test.auth {
				request.Header.Set("Authorization", "Bearer test-key")
			}
			if test.persistent {
				request.Header.Set("X-KeenPbr-Persist-Enabled", "1")
			}
			if test.temporary {
				request.Header.Set("X-KeenPbr-Temporary-Stop", "1")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || admin.calls != test.adminCalls || runtimeCalls != test.runtimeCalls {
				t.Fatalf("status=%d durable=%d temporary=%d", response.Code, admin.calls, runtimeCalls)
			}
			if admin.calls > 0 && (admin.tag != "proxy" || admin.enabled != (test.action == "up")) {
				t.Fatalf("wrong saved preference: tag=%q enabled=%v", admin.tag, admin.enabled)
			}
		})
	}
}

func TestPanelPowerNeverReportsSuccessWhenPersistenceFails(t *testing.T) {
	for _, available := range []bool{false, true} {
		var admin TransportAdmin = &exportAdminStub{}
		want := http.StatusServiceUnavailable
		if available {
			admin, want = &powerAdminStub{err: errors.New("save failed")}, http.StatusBadRequest
		}
		runtime := &shutdownRuntimeStub{operation: func(context.Context) error {
			t.Fatal("failed persistence must not fall back to a temporary action")
			return nil
		}}
		handler := New(runtime, "test-key", admin)
		request := httptest.NewRequest(http.MethodPost, "/v1/transports/proxy/down", nil)
		request.Header.Set("Authorization", "Bearer test-key")
		request.Header.Set("X-KeenPbr-Persist-Enabled", "1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("status=%d want=%d", response.Code, want)
		}
	}
}
