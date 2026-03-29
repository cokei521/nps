package p2pstate

import (
	"testing"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/p2p"
)

func TestRegistryLifecycle(t *testing.T) {
	const sessionID = "session-1"
	const token = "token-1"
	wire := p2p.NormalizeP2PWireSpec(p2p.P2PWireSpec{RouteID: "route-1"}, sessionID)
	routeKey := p2p.WireRouteKey(wire.RouteID)
	Register(sessionID, wire, token, time.Second)
	if !ValidateToken(sessionID, token) {
		t.Fatal("expected token to validate")
	}
	lookup, ok := LookupSession(routeKey)
	if !ok || lookup.SessionID != sessionID || lookup.Token != token {
		t.Fatalf("LookupSession() = %#v, %v", lookup, ok)
	}
	RecordObservation(routeKey, common.WORK_P2P_VISITOR, p2p.ProbeSample{
		ProbePort:       10206,
		ObservedAddr:    "1.1.1.1:4000",
		ServerReplyAddr: "1.1.1.1:4000",
	})
	RecordObservation(routeKey, common.WORK_P2P_VISITOR, p2p.ProbeSample{
		ProbePort:       10208,
		ObservedAddr:    "1.1.1.1:4004",
		ServerReplyAddr: "1.1.1.1:4004",
	})
	if !AcceptPacket(routeKey, time.Now().UnixMilli(), "nonce-1") {
		t.Fatal("expected AcceptPacket to accept the first nonce")
	}
	samples := GetObservations(sessionID, common.WORK_P2P_VISITOR)
	if len(samples) != 2 {
		t.Fatalf("len(samples) = %d, want 2", len(samples))
	}
	if samples[0].ProbePort != 10206 || samples[1].ProbePort != 10208 {
		t.Fatalf("unexpected sample ordering %#v", samples)
	}
	Unregister(sessionID)
	if ValidateToken(sessionID, token) {
		t.Fatal("token should be invalid after unregister")
	}
	if _, ok := LookupSession(routeKey); ok {
		t.Fatal("route lookup should be invalid after unregister")
	}
	if samples := GetObservations(sessionID, common.WORK_P2P_VISITOR); len(samples) != 0 {
		t.Fatalf("observations should be empty after unregister, got %#v", samples)
	}
}

func TestRegistryKeepsMultipleObservationsForSameProbePort(t *testing.T) {
	const sessionID = "session-2"
	const token = "token-2"
	wire := p2p.NormalizeP2PWireSpec(p2p.P2PWireSpec{RouteID: "route-2"}, sessionID)
	routeKey := p2p.WireRouteKey(wire.RouteID)
	Register(sessionID, wire, token, time.Second)
	t.Cleanup(func() { Unregister(sessionID) })

	RecordObservation(routeKey, common.WORK_P2P_VISITOR, p2p.ProbeSample{
		ProbePort:       10206,
		ObservedAddr:    "198.51.100.10:4000",
		ServerReplyAddr: "203.0.113.10:10206",
	})
	RecordObservation(routeKey, common.WORK_P2P_VISITOR, p2p.ProbeSample{
		ProbePort:       10206,
		ObservedAddr:    "[2001:db8::10]:4000",
		ServerReplyAddr: "[2001:db8::20]:10206",
	})

	samples := GetObservations(sessionID, common.WORK_P2P_VISITOR)
	if len(samples) != 2 {
		t.Fatalf("len(samples) = %d, want 2", len(samples))
	}
	if samples[0].ServerReplyAddr == samples[1].ServerReplyAddr {
		t.Fatalf("same probe port observations should be stored independently, got %#v", samples)
	}
}
