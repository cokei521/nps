package conn

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestDescribeNetErrorClassifiesRST(t *testing.T) {
	err := &net.OpError{
		Op:  "read",
		Net: "tcp",
		Err: syscall.ECONNRESET,
	}

	got := DescribeNetError(err, nil)
	if !strings.Contains(got, "kind=rst") {
		t.Fatalf("DescribeNetError() = %q, want kind=rst", got)
	}
	if !strings.Contains(got, "errno_name=ECONNRESET") {
		t.Fatalf("DescribeNetError() = %q, want errno_name=ECONNRESET", got)
	}
	if !strings.Contains(got, "op=read") {
		t.Fatalf("DescribeNetError() = %q, want op=read", got)
	}
}

func TestIsConnResetMatchesWindowsText(t *testing.T) {
	err := errors.New("wsarecv: An existing connection was forcibly closed by the remote host")
	if !IsConnReset(err) {
		t.Fatalf("IsConnReset(%v) = false, want true", err)
	}
}
