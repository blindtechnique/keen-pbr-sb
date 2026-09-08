package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	configpkg "github.com/infaprim/mykeenpbr/internal/config"
)

type shutdownRuntimeStub struct {
	readinessRuntimeStub
	operation func(context.Context) error
}

func (s *shutdownRuntimeStub) Up(ctx context.Context, _ string) error      { return s.operation(ctx) }
func (s *shutdownRuntimeStub) Down(ctx context.Context, _ string) error    { return s.operation(ctx) }
func (s *shutdownRuntimeStub) Restart(ctx context.Context, _ string) error { return s.operation(ctx) }

type shutdownSettingsStub struct {
	exportAdminStub
	operation func(context.Context) error
}

func (*shutdownSettingsStub) Settings() configpkg.RuntimeSettings { return configpkg.RuntimeSettings{} }
func (s *shutdownSettingsStub) SetSingBoxProcessMode(ctx context.Context, _ configpkg.SingBoxProcessMode) (configpkg.RuntimeSettings, error) {
	return configpkg.RuntimeSettings{}, s.operation(ctx)
}

func TestLifecycleActionsFollowServiceCancellationNotBrowser(t *testing.T) {
	for _, action := range []string{"up", "down", "restart", "settings"} {
		t.Run(action, func(t *testing.T) {
			serviceCtx, cancelService := context.WithCancel(context.Background())
			defer cancelService()
			entered := make(chan context.Context, 1)
			operation := func(ctx context.Context) error {
				entered <- ctx
				<-ctx.Done()
				return ctx.Err()
			}
			runtime := &shutdownRuntimeStub{operation: operation}
			admin := &shutdownSettingsStub{operation: operation}
			handler := NewWithContext(serviceCtx, runtime, "test-key", admin)
			method, path, body := http.MethodPost, "/v1/transports/proxy/"+action, ""
			if action == "settings" {
				method, path, body = http.MethodPut, "/v1/config/settings", `{"sing_box_process_mode":"isolated"}`
			}
			browserCtx, cancelBrowser := context.WithCancel(context.Background())
			cancelBrowser()
			request := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(browserCtx)
			request.Header.Set("Authorization", "Bearer test-key")
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { handler.ServeHTTP(response, request); close(done) }()
			var operationCtx context.Context
			select {
			case operationCtx = <-entered:
			case <-time.After(time.Second):
				t.Fatal("lifecycle action was not entered")
			}
			if err := operationCtx.Err(); err != nil {
				t.Fatalf("browser cancellation leaked into lifecycle action: %v", err)
			}
			cancelService()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("service cancellation did not drain the lifecycle action")
			}
			if !errors.Is(operationCtx.Err(), context.Canceled) {
				t.Fatalf("operation context error = %v", operationCtx.Err())
			}
			if response.Code != http.StatusBadRequest {
				t.Fatalf("canceled action response = %d", response.Code)
			}
			// An already accepted request may have been in flight during signal
			// delivery, but a later request must never start another operation.
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("shutdown admission response = %d", response.Code)
			}
			select {
			case <-entered:
				t.Fatal("shutdown accepted another lifecycle action")
			default:
			}
		})
	}
}
