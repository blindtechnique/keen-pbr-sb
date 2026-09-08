package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownDoesNotSpendTransportBudgetOnSlowHTTPBody(t *testing.T) {
	serviceCtx, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	entered := make(chan struct{})
	exited := make(chan struct{})
	server := &http.Server{
		BaseContext: func(net.Listener) context.Context { return serviceCtx },
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			close(entered)
			_, _ = io.ReadAll(request.Body)
			close(exited)
		}),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = fmt.Fprint(client, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the blocked body read")
	}
	cancelService()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	closedTransports := false
	err = shutdown(ctx, server, func(closeCtx context.Context) error {
		closedTransports = true
		if closeCtx != ctx || closeCtx.Err() != nil {
			t.Fatal("HTTP drain spent the shutdown budget before transport cleanup")
		}
		return nil
	})
	if !closedTransports || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("closed transports = %v, shutdown error = %v", closedTransports, err)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("expired HTTP drain left the request socket open")
	}
}

func TestShutdownPreservesTransportError(t *testing.T) {
	want := errors.New("transport cleanup failed")
	err := shutdown(context.Background(), &http.Server{}, func(context.Context) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("shutdown error = %v", err)
	}
}
