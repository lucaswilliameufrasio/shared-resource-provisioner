package httptransport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestHTTPShutdownDrainsInFlightRequestAndStopsAcceptingNewOnes(t *testing.T) {
	t.Parallel()

	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	shutdownStarted := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseHandler)
		})
	}

	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-releaseHandler
		writer.WriteHeader(http.StatusNoContent)
	})}
	server.RegisterOnShutdown(func() {
		close(shutdownStarted)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		release()
		_ = server.Close()
	})

	clientResult := make(chan error, 1)
	client := &http.Client{Timeout: 2 * time.Second}
	go func() {
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		clientResult <- err
	}()
	waitForHTTPTestSignal(t, handlerStarted)

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- shutdownHTTPServer(server, time.Second)
	}()
	waitForHTTPTestSignal(t, shutdownStarted)

	newClient := &http.Client{Timeout: 250 * time.Millisecond}
	if response, err := newClient.Get("http://" + listener.Addr().String()); err == nil {
		_ = response.Body.Close()
		t.Fatal("HTTP server accepted a request after shutdown began")
	}

	release()
	if err := <-clientResult; err != nil {
		t.Fatalf("in-flight request error = %v", err)
	}
	if err := <-shutdownResult; err != nil {
		t.Fatalf("shutdownHTTPServer() error = %v", err)
	}
	if err := <-serveResult; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve() error = %v, want http.ErrServerClosed", err)
	}
}

func TestHTTPShutdownTimeoutIsBounded(t *testing.T) {
	t.Parallel()

	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseHandler)
		})
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-releaseHandler
		writer.WriteHeader(http.StatusNoContent)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		release()
		_ = server.Close()
	})

	clientResult := make(chan error, 1)
	go func() {
		response, err := (&http.Client{Timeout: time.Second}).Get("http://" + listener.Addr().String())
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		clientResult <- err
	}()
	waitForHTTPTestSignal(t, handlerStarted)

	start := time.Now()
	err = shutdownHTTPServer(server, 25*time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdownHTTPServer() error = %v, want context deadline exceeded", err)
	}
	if elapsed > time.Second {
		t.Fatalf("shutdown duration = %s, want a bounded timeout under 1s", elapsed)
	}

	release()
	_ = server.Close()
	<-clientResult
	if err := <-serveResult; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve() error = %v, want http.ErrServerClosed", err)
	}
}

func TestHTTPShutdownGracePeriodCoversProvisioningAndCleanupWindow(t *testing.T) {
	const minimumOperationAndCleanupWindow = 55 * time.Second
	if httpShutdownGracePeriod < minimumOperationAndCleanupWindow {
		t.Fatalf("HTTP shutdown grace = %s, want at least %s", httpShutdownGracePeriod, minimumOperationAndCleanupWindow)
	}
}

func waitForHTTPTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP test server state transition")
	}
}
