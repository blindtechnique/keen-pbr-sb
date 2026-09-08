package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// The test binary acts as an owned sing-box child on both Linux and Windows.
// A local echo socket proves process liveness without reading a PID table or
// racing exec.Cmd.Wait's ProcessState field.
func TestMain(m *testing.M) {
	if os.Getenv("KPBR_SHUTDOWN_TEST_CHILD") == "1" && len(os.Args) > 1 {
		switch os.Args[1] {
		case "check":
			os.Exit(0)
		case "run":
			connection, err := net.Dial("tcp", os.Getenv("KPBR_SHUTDOWN_TEST_SOCKET"))
			if err != nil {
				os.Exit(2)
			}
			_, _ = connection.Write([]byte("R"))
			_, _ = io.Copy(connection, connection)
			_ = connection.Close()
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestSingBoxBusyLifecycleHonorsDeadline(t *testing.T) {
	for _, action := range []string{"up", "down"} {
		t.Run(action, func(t *testing.T) {
			s := &SingBox{state: StateUp}
			s.opMu.Lock()
			defer s.opMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if action == "up" {
					done <- s.Up(ctx)
				} else {
					done <- s.Down(ctx)
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("action error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("busy lifecycle ignored its deadline")
			}
			if s.state != StateUp {
				t.Fatal("timed-out mutex wait changed transport state")
			}
		})
	}
}

type blockingStartupFirewallRunner struct {
	*fakeFirewallRunner
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (r *blockingStartupFirewallRunner) Run(ctx context.Context, binary string, args []string) firewallCommandResult {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.fakeFirewallRunner.Run(ctx, binary, args)
}

func isolatedShutdownFixture(t *testing.T, runner firewallCommandRunner) (*SingBox, *net.TCPListener) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("KPBR_SHUTDOWN_TEST_CHILD", "1")
	t.Setenv("KPBR_SHUTDOWN_TEST_SOCKET", listener.Addr().String())
	original := systemForwardingRules
	systemForwardingRules = newForwardingRuleManager(runner)
	t.Cleanup(func() { systemForwardingRules = original })
	s := &SingBox{
		spec:   TransportSpec{Tag: "proxy", Type: "sing-box", Interface: "testtun", OutboundJSON: `{"type":"direct"}`},
		binary: binary, runtimeDir: t.TempDir(),
		interfaceByName: func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil },
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Down(ctx)
	})
	return s, listener
}

func acceptShutdownChild(t *testing.T, listener *net.TCPListener) net.Conn {
	t.Helper()
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	var ready [1]byte
	if _, err := io.ReadFull(connection, ready[:]); err != nil || ready[0] != 'R' {
		t.Fatalf("child readiness = %q, %v", ready, err)
	}
	return connection
}

func requireChildStopped(t *testing.T, connection net.Conn) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	_, err := connection.Read(data[:])
	if err == nil {
		t.Fatal("stopped child returned unexpected data")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("owned process remained alive after cancellation")
	}
}

func TestSingBoxCancellationDuringForwardingStopsOwnedProcess(t *testing.T) {
	runner := &blockingStartupFirewallRunner{fakeFirewallRunner: newFakeFirewallRunner(), entered: make(chan struct{}), release: make(chan struct{})}
	s, listener := isolatedShutdownFixture(t, runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runner.release) }) }
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() { done <- s.Up(ctx) }()
	connection := acceptShutdownChild(t, listener)
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("Up did not enter forwarding setup")
	}
	cancel()
	// Do not unblock forwarding until the child has actually exited. This
	// catches the original readiness-select cancellation blind spot.
	requireChildStopped(t, connection)
	release()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Up error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled Up did not finish after forwarding was released")
	}
}

func TestSingBoxSuccessfulUpDetachesCancellationAndExpiredCloseStillStops(t *testing.T) {
	s, listener := isolatedShutdownFixture(t, newFakeFirewallRunner())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upDone := make(chan error, 1)
	go func() { upDone <- s.Up(ctx) }()
	connection := acceptShutdownChild(t, listener)
	select {
	case err := <-upDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Up did not finish")
	}
	cancel() // Equivalent to the successful API action's deferred cancel.
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("still up")); err != nil {
		t.Fatal(err)
	}
	var echo [8]byte
	if _, err := io.ReadFull(connection, echo[:]); err != nil || string(echo[:]) != "still up" {
		t.Fatalf("successful Up retained cancellation callback: %q, %v", echo, err)
	}
	s.mu.Lock()
	processDone := s.done
	s.mu.Unlock()
	manager := NewManager()
	if err := manager.Add(s); err != nil {
		t.Fatal(err)
	}
	// Earlier processes can exhaust Manager.Close's shared budget. An idle
	// remaining process must still get the existing immediate Signal/Kill.
	if err := manager.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expired Close error = %v", err)
	}
	requireChildStopped(t, connection)
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not reap its owned child")
	}
}
