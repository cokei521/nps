package mux

import (
	"net"
	"strings"
	"testing"
)

func TestMuxAcceptReturnsCloseReason(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	m := NewMux(server, "tcp", 30, true)
	reason := "read session unpack failed: kind=rst err=\"connection reset by peer\""
	if err := m.closeWithReason(reason); err != nil {
		t.Fatalf("closeWithReason() error = %v", err)
	}

	_, err := m.Accept()
	if err == nil {
		t.Fatal("Accept() error = nil, want close reason")
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("Accept() error = %q, want reason %q", err.Error(), reason)
	}
	if got := m.CloseReason(); got != reason {
		t.Fatalf("CloseReason() = %q, want %q", got, reason)
	}
}
