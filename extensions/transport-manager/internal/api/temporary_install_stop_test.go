package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type installStopRuntimeStub struct {
	readinessRuntimeStub
	status transport.Status
	down   func(context.Context) error
	up     func(context.Context) error
}

func (s *installStopRuntimeStub) Status(context.Context, string) (transport.Status, error) {
	return s.status, nil
}
func (s *installStopRuntimeStub) Down(ctx context.Context, _ string) error { return s.down(ctx) }
func (s *installStopRuntimeStub) Up(ctx context.Context, _ string) error   { return s.up(ctx) }

func waitInstallStop(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("temporary install action did not reach the expected phase")
	}
}

func TestTemporaryInstallStopRestoresLateDownAfterClientResume(t *testing.T) {
	for _, reason := range []string{"request disconnected", "server deadline"} {
		t.Run(reason, func(t *testing.T) {
			requestCtx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			entered, canceled, releaseDown := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var desired atomic.Bool
			desired.Store(true)
			var resumed atomic.Int32
			runtime := &installStopRuntimeStub{
				status: transport.Status{Type: "sing-box", State: transport.StateStarting, DesiredUp: true},
				down: func(ctx context.Context) error {
					close(entered)
					<-ctx.Done()
					close(canceled)
					// A shared transition is allowed to finish after its caller
					// cancels. Deliberately let the C++ resume overtake it.
					<-releaseDown
					desired.Store(false)
					return nil
				},
				up: func(ctx context.Context) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					desired.Store(true)
					resumed.Add(1)
					return nil
				},
			}
			a := &API{manager: runtime, lifecycle: context.Background()}
			timeout := time.Hour
			if reason == "server deadline" {
				timeout = 10 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() { done <- a.temporaryInstallStop(requestCtx, "proxy", timeout) }()
			waitInstallStop(t, entered)
			if reason == "request disconnected" {
				cancelRequest()
			}
			waitInstallStop(t, canceled)
			if err := runtime.Up(context.Background(), "proxy"); err != nil {
				t.Fatal(err)
			}
			if resumed.Load() != 1 {
				t.Fatal("server resumed before the late Down had returned")
			}
			close(releaseDown)
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("temporary stop error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("late Down was not followed by compensation")
			}
			if !desired.Load() || resumed.Load() != 2 {
				t.Fatalf("late Down won over resume: desired=%v resumes=%d", desired.Load(), resumed.Load())
			}
		})
	}
}

func TestTemporaryInstallStopRestoresQueuedOrFailedDown(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed after changing intent", true: "queued until deadline"}[queued], func(t *testing.T) {
			resumed := false
			runtime := &installStopRuntimeStub{
				status: transport.Status{Type: "sing-box", State: transport.StateDegraded, DesiredUp: true},
				down: func(ctx context.Context) error {
					if queued {
						// Models the existing context-aware opMu wait. No FIFO
						// guarantee is needed after this wait is canceled.
						<-ctx.Done()
						return ctx.Err()
					}
					return errors.New("stop failed after desired became false")
				},
				up: func(ctx context.Context) error {
					resumed = ctx.Err() == nil
					return ctx.Err()
				},
			}
			a := &API{manager: runtime, lifecycle: context.Background()}
			if err := a.temporaryInstallStop(context.Background(), "proxy", 10*time.Millisecond); err == nil || !resumed {
				t.Fatalf("failed temporary stop did not restore intent: error=%v resumed=%v", err, resumed)
			}
		})
	}
}

func TestTemporaryInstallStopDoesNotResumeAfterServiceShutdown(t *testing.T) {
	serviceCtx, stopService := context.WithCancel(context.Background())
	defer stopService()
	resumed := false
	runtime := &installStopRuntimeStub{
		status: transport.Status{Type: "sing-box", State: transport.StateUp, PID: 42},
		down:   func(ctx context.Context) error { stopService(); <-ctx.Done(); return ctx.Err() },
		up:     func(context.Context) error { resumed = true; return nil },
	}
	a := &API{manager: runtime, lifecycle: serviceCtx}
	if err := a.temporaryInstallStop(context.Background(), "proxy", time.Hour); !errors.Is(err, context.Canceled) || resumed {
		t.Fatalf("shutdown compensation restarted a transport: error=%v resumed=%v", err, resumed)
	}
}

func TestTemporaryInstallStopPreservesSuccessfulAndInactiveState(t *testing.T) {
	for _, state := range []string{"running", "inactive", "native"} {
		t.Run(state, func(t *testing.T) {
			downCalls, upCalls := 0, 0
			status := transport.Status{Type: "sing-box", State: transport.StateDown}
			if state == "running" {
				status.PID, status.State = 42, transport.StateUp
			} else if state == "native" {
				status.Type, status.State = "native", transport.StateUp
			}
			runtime := &installStopRuntimeStub{
				status: status,
				down:   func(context.Context) error { downCalls++; return nil },
				up:     func(context.Context) error { upCalls++; return nil },
			}
			handler := NewWithContext(context.Background(), runtime, "test-key")
			request := httptest.NewRequest(http.MethodPost, "/v1/transports/proxy/down", nil)
			request.Header.Set("Authorization", "Bearer test-key")
			request.Header.Set("X-KeenPbr-Temporary-Stop", "1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantDown, wantCode := 0, http.StatusAccepted
			if state == "running" {
				wantDown = 1
			} else if state == "native" {
				wantCode = http.StatusBadRequest
			}
			if response.Code != wantCode || downCalls != wantDown || upCalls != 0 {
				t.Fatalf("state changed unexpectedly: response=%d down=%d up=%d", response.Code, downCalls, upCalls)
			}
		})
	}
}
