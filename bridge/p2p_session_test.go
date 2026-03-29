package bridge

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/p2p"
	"github.com/djylb/nps/server/connection"
	"github.com/djylb/nps/server/p2pstate"
)

func TestP2PBridgeSessionAbortStillRelaysAfterSummary(t *testing.T) {
	visitorServer, visitorClient := net.Pipe()
	providerServer, providerClient := net.Pipe()
	defer func() { _ = visitorServer.Close() }()
	defer func() { _ = visitorClient.Close() }()
	defer func() { _ = providerServer.Close() }()
	defer func() { _ = providerClient.Close() }()

	session := &p2pBridgeSession{
		mgr:             newP2PSessionManager(),
		id:              "session-1",
		token:           "token-1",
		timeouts:        p2p.P2PTimeouts{ProbeTimeoutMs: 1000, HandshakeTimeoutMs: 1000, TransportTimeoutMs: 1000},
		visitorControl:  conn.NewConn(visitorServer),
		providerControl: conn.NewConn(providerServer),
		visitorReport: &p2p.P2PProbeReport{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_VISITOR,
			PeerRole:  common.WORK_P2P_PROVIDER,
			Self:      p2p.P2PPeerInfo{Role: common.WORK_P2P_VISITOR},
		},
		providerReport: &p2p.P2PProbeReport{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_PROVIDER,
			PeerRole:  common.WORK_P2P_VISITOR,
			Self:      p2p.P2PPeerInfo{Role: common.WORK_P2P_PROVIDER},
		},
		timer: time.NewTimer(time.Minute),
	}
	session.mgr.sessions.Store(session.id, session)
	p2pstate.Register(session.id, p2p.P2PWireSpec{RouteID: session.id}, session.token, time.Minute)
	defer p2pstate.Unregister(session.id)

	type result struct {
		flag  string
		abort p2p.P2PPunchAbort
		err   error
	}
	readSide := func(c net.Conn) <-chan result {
		out := make(chan result, 1)
		go func() {
			defer close(out)
			cc := conn.NewConn(c)
			if _, err := p2p.ReadBridgeJSON[p2p.P2PProbeSummary](cc, common.P2P_PROBE_SUMMARY); err != nil {
				out <- result{err: err}
				return
			}
			flag, err := cc.ReadFlag()
			if err != nil {
				out <- result{err: err}
				return
			}
			raw, err := cc.GetShortLenContent()
			if err != nil {
				out <- result{err: err}
				return
			}
			var abort p2p.P2PPunchAbort
			if err := json.Unmarshal(raw, &abort); err != nil {
				out <- result{err: err}
				return
			}
			out <- result{flag: flag, abort: abort}
		}()
		return out
	}

	visitorDone := readSide(visitorClient)
	providerDone := readSide(providerClient)

	session.sendSummary()
	session.abort("late failure")

	visitorResult := <-visitorDone
	providerResult := <-providerDone
	if visitorResult.err != nil {
		t.Fatalf("visitor side read failed: %v", visitorResult.err)
	}
	if providerResult.err != nil {
		t.Fatalf("provider side read failed: %v", providerResult.err)
	}
	if visitorResult.flag != common.P2P_PUNCH_ABORT || providerResult.flag != common.P2P_PUNCH_ABORT {
		t.Fatalf("unexpected abort flags visitor=%q provider=%q", visitorResult.flag, providerResult.flag)
	}
	if visitorResult.abort.Reason != "late failure" || providerResult.abort.Reason != "late failure" {
		t.Fatalf("unexpected abort payload visitor=%#v provider=%#v", visitorResult.abort, providerResult.abort)
	}
}

func TestCollectProbeBaseHostsIncludesBridgeAndConfiguredFamilies(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		serverConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		serverConnCh <- serverConn
	}()

	clientConn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	serverConn := <-serverConnCh
	defer func() { _ = serverConn.Close() }()

	oldP2pIP := connection.P2pIp
	connection.P2pIp = "::1"
	defer func() { connection.P2pIp = oldP2pIP }()

	hosts := collectProbeBaseHosts(conn.NewConn(serverConn))
	if len(hosts) < 2 {
		t.Fatalf("expected dual-family probe hosts, got %#v", hosts)
	}
	if hosts[0] != "127.0.0.1" {
		t.Fatalf("hosts[0] = %q, want bridge local IPv4", hosts[0])
	}
	foundIPv6 := false
	for _, host := range hosts {
		if host == "::1" {
			foundIPv6 = true
			break
		}
	}
	if !foundIPv6 {
		t.Fatalf("expected configured IPv6 probe host in %#v", hosts)
	}
}

func TestBuildProbeOptionsIncludesPCPFlag(t *testing.T) {
	options := buildProbeOptions()
	value, ok := options["enable_pcp_portmap"]
	if !ok {
		t.Fatal("enable_pcp_portmap should be present in bridge probe options")
	}
	if value != "true" && value != "false" {
		t.Fatalf("unexpected enable_pcp_portmap value %q", value)
	}
}

func TestP2PBridgeSessionSendsGoAfterBothSidesReady(t *testing.T) {
	visitorServer, visitorClient := net.Pipe()
	providerServer, providerClient := net.Pipe()
	defer func() { _ = visitorServer.Close() }()
	defer func() { _ = visitorClient.Close() }()
	defer func() { _ = providerServer.Close() }()
	defer func() { _ = providerClient.Close() }()

	session := &p2pBridgeSession{
		mgr:             newP2PSessionManager(),
		id:              "session-go",
		token:           "token-go",
		timeouts:        p2p.P2PTimeouts{ProbeTimeoutMs: 1000, HandshakeTimeoutMs: 1000, TransportTimeoutMs: 1000},
		visitorControl:  conn.NewConn(visitorServer),
		providerControl: conn.NewConn(providerServer),
		visitorReport: &p2p.P2PProbeReport{
			SessionID: "session-go",
			Token:     "token-go",
			Role:      common.WORK_P2P_VISITOR,
			PeerRole:  common.WORK_P2P_PROVIDER,
			Self:      p2p.P2PPeerInfo{Role: common.WORK_P2P_VISITOR},
		},
		providerReport: &p2p.P2PProbeReport{
			SessionID: "session-go",
			Token:     "token-go",
			Role:      common.WORK_P2P_PROVIDER,
			PeerRole:  common.WORK_P2P_VISITOR,
			Self:      p2p.P2PPeerInfo{Role: common.WORK_P2P_PROVIDER},
		},
		timer: time.NewTimer(time.Minute),
	}

	type result struct {
		goMsg p2p.P2PPunchGo
		err   error
	}
	readSide := func(c net.Conn) <-chan result {
		out := make(chan result, 1)
		go func() {
			defer close(out)
			cc := conn.NewConn(c)
			if _, err := p2p.ReadBridgeJSON[p2p.P2PProbeSummary](cc, common.P2P_PROBE_SUMMARY); err != nil {
				out <- result{err: err}
				return
			}
			goMsg, err := p2p.ReadBridgeJSON[p2p.P2PPunchGo](cc, common.P2P_PUNCH_GO)
			out <- result{goMsg: goMsg, err: err}
		}()
		return out
	}

	visitorDone := readSide(visitorClient)
	providerDone := readSide(providerClient)
	session.sendSummary()
	session.handleReady(common.WORK_P2P_VISITOR, &p2p.P2PPunchReady{SessionID: session.id, Role: common.WORK_P2P_VISITOR})
	session.handleReady(common.WORK_P2P_PROVIDER, &p2p.P2PPunchReady{SessionID: session.id, Role: common.WORK_P2P_PROVIDER})

	visitorResult := <-visitorDone
	providerResult := <-providerDone
	if visitorResult.err != nil {
		t.Fatalf("visitor side read failed: %v", visitorResult.err)
	}
	if providerResult.err != nil {
		t.Fatalf("provider side read failed: %v", providerResult.err)
	}
	if visitorResult.goMsg.SessionID != session.id || providerResult.goMsg.SessionID != session.id {
		t.Fatalf("unexpected go payload visitor=%#v provider=%#v", visitorResult.goMsg, providerResult.goMsg)
	}
	if visitorResult.goMsg.DelayMs <= 0 || providerResult.goMsg.DelayMs <= 0 {
		t.Fatalf("go delay must be positive visitor=%#v provider=%#v", visitorResult.goMsg, providerResult.goMsg)
	}
}

func TestP2PBridgeSessionSummaryRetainsPostSummaryTimeout(t *testing.T) {
	mgr := newP2PSessionManager()
	session := &p2pBridgeSession{
		mgr:      mgr,
		id:       "session-post-summary-timeout",
		token:    "token-post-summary-timeout",
		timeouts: p2p.P2PTimeouts{HandshakeTimeoutMs: 20, TransportTimeoutMs: 20},
		visitorReport: &p2p.P2PProbeReport{
			SessionID: "session-post-summary-timeout",
			Token:     "token-post-summary-timeout",
			Role:      common.WORK_P2P_VISITOR,
			PeerRole:  common.WORK_P2P_PROVIDER,
			Self:      p2p.P2PPeerInfo{Role: common.WORK_P2P_VISITOR},
		},
		providerReport: &p2p.P2PProbeReport{
			SessionID: "session-post-summary-timeout",
			Token:     "token-post-summary-timeout",
			Role:      common.WORK_P2P_PROVIDER,
			PeerRole:  common.WORK_P2P_VISITOR,
			Self:      p2p.P2PPeerInfo{Role: common.WORK_P2P_PROVIDER},
		},
		telemetry: newP2PSessionTelemetry(time.Now()),
	}
	mgr.sessions.Store(session.id, session)

	session.sendSummary()

	if _, ok := mgr.get(session.id); !ok {
		t.Fatal("session should remain managed after summary until transport completes or times out")
	}
	if session.telemetrySnapshot().SummaryAtMs == 0 {
		t.Fatal("summary telemetry should be recorded")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		session.mu.Lock()
		closed := session.closed
		timer := session.timer
		session.mu.Unlock()
		if closed {
			break
		}
		if timer == nil {
			t.Fatal("post-summary timeout timer should remain active")
		}
		if time.Now().After(deadline) {
			t.Fatal("post-summary timeout should abort stalled session")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := mgr.get(session.id); ok {
		t.Fatal("timed-out post-summary session should be removed from manager")
	}
}

func TestBuildSummaryHintsIncludesFamilyBreakdown(t *testing.T) {
	self := p2p.BuildPeerInfo(common.WORK_P2P_VISITOR, common.CONN_KCP, "", []p2p.P2PFamilyInfo{
		{
			Family: "udp4",
			Nat: p2p.NatObservation{
				NATType:             p2p.NATTypeRestrictedCone,
				MappingBehavior:     p2p.NATMappingEndpointIndependent,
				FilteringBehavior:   p2p.NATFilteringPortRestricted,
				ClassificationLevel: p2p.ClassificationConfidenceMed,
				ProbeEndpointCount:  3,
				Samples:             []p2p.ProbeSample{{Provider: p2p.ProbeProviderNPS}},
			},
		},
		{
			Family: "udp6",
			Nat: p2p.NatObservation{
				NATType:             p2p.NATTypeCone,
				MappingBehavior:     p2p.NATMappingEndpointIndependent,
				ClassificationLevel: p2p.ClassificationConfidenceHigh,
				ProbeEndpointCount:  2,
				Samples:             []p2p.ProbeSample{{Provider: p2p.ProbeProviderSTUN}},
			},
		},
	})
	peer := p2p.BuildPeerInfo(common.WORK_P2P_PROVIDER, common.CONN_KCP, "", []p2p.P2PFamilyInfo{
		{
			Family: "udp4",
			Nat:    p2p.NatObservation{NATType: p2p.NATTypePortRestricted},
		},
	})

	hints := buildSummaryHints(self, peer)
	if got := hints["shared_family_count"]; got != 1 {
		t.Fatalf("shared_family_count = %#v, want 1", got)
	}
	if got := hints["dual_stack_parallel"]; got != false {
		t.Fatalf("dual_stack_parallel = %#v, want false", got)
	}
	selfFamilies, ok := hints["self_family_details"].(map[string]map[string]any)
	if !ok {
		t.Fatalf("self_family_details type = %T", hints["self_family_details"])
	}
	if _, ok := selfFamilies["udp4"]; !ok {
		t.Fatalf("self_family_details missing udp4: %#v", selfFamilies)
	}
	if _, ok := selfFamilies["udp6"]; !ok {
		t.Fatalf("self_family_details missing udp6: %#v", selfFamilies)
	}
}

func TestP2PBridgeSessionTelemetryAggregatesSuccess(t *testing.T) {
	session := &p2pBridgeSession{
		id:        "session-telemetry",
		telemetry: newP2PSessionTelemetry(time.Now()),
	}
	session.handleProgress(&p2p.P2PPunchProgress{
		SessionID: "session-telemetry",
		Role:      common.WORK_P2P_VISITOR,
		Stage:     "family_ready",
		Status:    "ok",
		LocalAddr: "127.0.0.1:1000",
		Meta: map[string]string{
			"family":          "udp4",
			"transport_mode":  common.CONN_KCP,
			"candidate_score": "42",
		},
		Counters: map[string]int{"total": 2},
	})
	session.handleProgress(&p2p.P2PPunchProgress{
		SessionID:  "session-telemetry",
		Role:       common.WORK_P2P_VISITOR,
		Stage:      "transport_established",
		Status:     "ok",
		Detail:     common.CONN_KCP,
		LocalAddr:  "127.0.0.1:1000",
		RemoteAddr: "198.51.100.10:4000",
		Meta:       map[string]string{"family": "udp4"},
	})
	session.handleProgress(&p2p.P2PPunchProgress{
		SessionID:  "session-telemetry",
		Role:       common.WORK_P2P_PROVIDER,
		Stage:      "transport_established",
		Status:     "ok",
		Detail:     common.CONN_KCP,
		LocalAddr:  "127.0.0.1:2000",
		RemoteAddr: "198.51.100.20:5000",
		Meta:       map[string]string{"family": "udp4"},
	})

	snapshot := session.telemetrySnapshot()
	if snapshot.Outcome != "transport_established" {
		t.Fatalf("telemetry outcome = %q, want transport_established", snapshot.Outcome)
	}
	visitor := snapshot.Roles[common.WORK_P2P_VISITOR]
	if !visitor.TransportEstablished || visitor.LastFamily != "udp4" {
		t.Fatalf("unexpected visitor telemetry %#v", visitor)
	}
	if visitor.Counters["total"] != 2 {
		t.Fatalf("visitor counters = %#v, want total=2", visitor.Counters)
	}
	if visitor.Stages["family_ready"].Count != 1 {
		t.Fatalf("family_ready stage = %#v", visitor.Stages["family_ready"])
	}
}

func TestP2PBridgeSessionSuccessClosesControlConns(t *testing.T) {
	visitorServer, visitorClient := net.Pipe()
	providerServer, providerClient := net.Pipe()
	defer func() { _ = visitorClient.Close() }()
	defer func() { _ = providerClient.Close() }()
	mgr := newP2PSessionManager()

	session := &p2pBridgeSession{
		mgr:             mgr,
		id:              "session-success-close",
		visitorControl:  conn.NewConn(visitorServer),
		providerControl: conn.NewConn(providerServer),
		timer:           time.NewTimer(time.Minute),
		telemetry:       newP2PSessionTelemetry(time.Now()),
	}
	mgr.sessions.Store(session.id, session)

	session.handleProgress(&p2p.P2PPunchProgress{
		SessionID: "session-success-close",
		Role:      common.WORK_P2P_VISITOR,
		Stage:     "transport_established",
		Status:    "ok",
	})
	session.handleProgress(&p2p.P2PPunchProgress{
		SessionID: "session-success-close",
		Role:      common.WORK_P2P_PROVIDER,
		Stage:     "transport_established",
		Status:    "ok",
	})

	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		session.mu.Lock()
		closed := session.closed
		visitorControl := session.visitorControl
		providerControl := session.providerControl
		session.mu.Unlock()
		if closed && visitorControl == nil && providerControl == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("successful session should release bridge control connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := mgr.get(session.id); ok {
		t.Fatal("successful session should be removed from session manager")
	}
}

func TestP2PBridgeSessionAbortPendingUsesClosingRoleState(t *testing.T) {
	session := &p2pBridgeSession{
		id:          "session-abort-pending",
		summarySent: true,
		goSent:      true,
		timer:       time.NewTimer(time.Minute),
		telemetry:   newP2PSessionTelemetry(time.Now()),
	}
	session.telemetry.recordProgress(p2p.P2PPunchProgress{
		SessionID: "session-abort-pending",
		Role:      common.WORK_P2P_VISITOR,
		Stage:     "transport_established",
		Status:    "ok",
	})

	session.abortPending(common.WORK_P2P_VISITOR, "visitor control closed")
	session.mu.Lock()
	closedAfterVisitor := session.closed
	session.mu.Unlock()
	if closedAfterVisitor {
		t.Fatal("session should not abort when the already-established role closes its control connection")
	}

	session.abortPending(common.WORK_P2P_PROVIDER, "provider control closed")
	session.mu.Lock()
	closedAfterProvider := session.closed
	session.mu.Unlock()
	if !closedAfterProvider {
		t.Fatal("session should abort when a not-yet-established role loses its control connection")
	}
}

func TestP2PSessionManagerGetRejectsClosedSession(t *testing.T) {
	mgr := newP2PSessionManager()
	session := &p2pBridgeSession{id: "session-closed", closed: true}
	mgr.sessions.Store(session.id, session)

	if _, ok := mgr.get(session.id); ok {
		t.Fatal("get() should reject closed sessions")
	}
	if _, exists := mgr.sessions.Load(session.id); exists {
		t.Fatal("closed session should be evicted from the session manager")
	}
}

func TestP2PBridgeSessionAttachProviderRejectsDuplicateOrClosed(t *testing.T) {
	session := &p2pBridgeSession{}
	first := &conn.Conn{}
	second := &conn.Conn{}
	if !session.attachProvider(first) {
		t.Fatal("first provider attach should succeed")
	}
	if session.attachProvider(second) {
		t.Fatal("duplicate provider attach should be rejected")
	}
	session.closed = true
	if session.attachProvider(first) {
		t.Fatal("closed session should reject provider attach")
	}
}

func TestPunchGoDelayMsAdaptsToSummaryHints(t *testing.T) {
	easyDelay := punchGoDelayMs(p2p.P2PTimeouts{HandshakeTimeoutMs: 2000}, map[string]any{
		"shared_family_count":       2,
		"self_filtering_tested":     true,
		"peer_filtering_tested":     true,
		"self_probe_provider_count": 2,
		"peer_probe_provider_count": 2,
	})
	hardDelay := punchGoDelayMs(p2p.P2PTimeouts{HandshakeTimeoutMs: 2000}, map[string]any{
		"mapping_confidence_low":    true,
		"probe_port_restricted":     true,
		"self_filtering_tested":     false,
		"peer_filtering_tested":     true,
		"self_probe_provider_count": 1,
		"peer_probe_provider_count": 1,
	})
	if easyDelay >= hardDelay {
		t.Fatalf("easy delay %d should be lower than hard delay %d", easyDelay, hardDelay)
	}
	if easyDelay < 40 || hardDelay < easyDelay {
		t.Fatalf("unexpected delays easy=%d hard=%d", easyDelay, hardDelay)
	}
}

func TestPostSummaryTTLUsesHandshakeAndTransportBudget(t *testing.T) {
	if got := postSummaryTTL(p2p.P2PTimeouts{}); got != 20*time.Second {
		t.Fatalf("postSummaryTTL(zero) = %s, want 20s", got)
	}
	if got := postSummaryTTL(p2p.P2PTimeouts{HandshakeTimeoutMs: 50, TransportTimeoutMs: 50}); got != 1100*time.Millisecond {
		t.Fatalf("postSummaryTTL(50ms,50ms) = %s, want 1100ms", got)
	}
	if got := postSummaryTTL(p2p.P2PTimeouts{HandshakeTimeoutMs: 0, TransportTimeoutMs: -800}); got != 20*time.Second {
		t.Fatalf("postSummaryTTL(invalid) = %s, want 20s", got)
	}
}
