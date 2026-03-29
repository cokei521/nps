package client

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/djylb/nps/lib/conn"
)

func TestP2pBridgeSendLinkInfoUsesConfiguredTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := &P2PManager{
		ctx:      ctx,
		cancel:   cancel,
		statusCh: make(chan struct{}, 1),
	}
	bridge := &P2pBridge{
		mgr:     mgr,
		p2p:     true,
		secret:  false,
		timeout: 50 * time.Millisecond,
	}

	started := time.Now()
	_, err := bridge.SendLinkInfo(0, &conn.Link{}, nil)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "timeout waiting P2P tunnel") {
		t.Fatalf("SendLinkInfo() error = %v, want timeout", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("SendLinkInfo() returned too early after %s", elapsed)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("SendLinkInfo() ignored configured timeout, elapsed=%s", elapsed)
	}
}

func TestPreferredP2PLocalAddrNormalizesWildcardAndIPv6(t *testing.T) {
	if got := preferredP2PLocalAddr(""); got != "" {
		t.Fatalf("preferredP2PLocalAddr(\"\") = %q, want empty", got)
	}
	if got := preferredP2PLocalAddr("0.0.0.0"); got != "" {
		t.Fatalf("preferredP2PLocalAddr(0.0.0.0) = %q, want empty", got)
	}
	if got := preferredP2PLocalAddr("[::]"); got != "" {
		t.Fatalf("preferredP2PLocalAddr([::]) = %q, want empty", got)
	}
	if got := preferredP2PLocalAddr("[2001:db8::10]"); got != "2001:db8::10" {
		t.Fatalf("preferredP2PLocalAddr([2001:db8::10]) = %q", got)
	}
}

func TestP2PHardNATRetryDelayBackoffAndCap(t *testing.T) {
	tests := []struct {
		level int
		want  time.Duration
	}{
		{level: 0, want: 15 * time.Second},
		{level: 1, want: 15 * time.Second},
		{level: 2, want: 30 * time.Second},
		{level: 3, want: time.Minute},
		{level: 4, want: 2 * time.Minute},
		{level: 8, want: 2 * time.Minute},
	}
	for _, tt := range tests {
		if got := p2pHardNATRetryDelay(tt.level); got != tt.want {
			t.Fatalf("p2pHardNATRetryDelay(%d) = %s, want %s", tt.level, got, tt.want)
		}
	}
}

func TestP2PManagerCloseDoesNotHoldLockDuringTransportClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := &P2PManager{
		ctx:      ctx,
		cancel:   cancel,
		statusCh: make(chan struct{}, 1),
	}
	closed := make(chan struct{})
	mgr.mu.Lock()
	mgr.udpConn = &reentrantCloseConn{
		closeFn: func() {
			mgr.resetStatus(false)
			close(closed)
		},
	}
	mgr.statusOK = true
	mgr.mu.Unlock()

	done := make(chan struct{})
	go func() {
		mgr.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close() should not deadlock while closing active transport")
	}
	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("active transport Close() was not reached")
	}
}

func TestCloseP2PTransportClosesQuicPacketConn(t *testing.T) {
	closed := make(chan struct{}, 1)
	closeP2PTransport(p2pTransportState{
		quicPacket: &closeSpyPacketConn{
			closeFn: func() {
				select {
				case closed <- struct{}{}:
				default:
				}
			},
		},
	}, "test")

	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("closeP2PTransport() should close the retained QUIC packet conn")
	}
}

type reentrantCloseConn struct {
	closeFn func()
}

func (c *reentrantCloseConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *reentrantCloseConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *reentrantCloseConn) Close() error {
	if c.closeFn != nil {
		c.closeFn()
	}
	return nil
}
func (c *reentrantCloseConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (c *reentrantCloseConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (c *reentrantCloseConn) SetDeadline(time.Time) error      { return nil }
func (c *reentrantCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *reentrantCloseConn) SetWriteDeadline(time.Time) error { return nil }

type closeSpyPacketConn struct {
	closeFn func()
}

func (c *closeSpyPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}
func (c *closeSpyPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *closeSpyPacketConn) Close() error {
	if c.closeFn != nil {
		c.closeFn()
	}
	return nil
}
func (c *closeSpyPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *closeSpyPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *closeSpyPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeSpyPacketConn) SetWriteDeadline(time.Time) error { return nil }
