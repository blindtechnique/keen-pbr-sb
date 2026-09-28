package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type serviceRuntimeStub struct {
	readinessRuntimeStub
	actions []string
}

func (s *serviceRuntimeStub) ServiceAction(ctx context.Context, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.actions = append(s.actions, action)
	return nil
}

func TestSingBoxServiceAPIUsesOneCommandAndSurvivesBrowserCancellation(t *testing.T) {
	runtime := &serviceRuntimeStub{}
	handler := New(runtime, "secret")
	for _, action := range []string{"down", "up", "restart"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequest(http.MethodPost, "/v1/sing-box/"+action, nil).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("%s: %d %s", action, response.Code, response.Body.String())
		}
	}
	if len(runtime.actions) != 3 {
		t.Fatal("service command was fanned out to transports")
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/sing-box/restart", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(runtime.actions) != 3 {
		t.Fatal("service action bypassed authentication")
	}
}
