package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	pionstun "github.com/pion/stun/v3"
)

func resetPredictionHistoryForTest() {
	globalPredictionHistory.mu.Lock()
	defer globalPredictionHistory.mu.Unlock()
	globalPredictionHistory.entries = make(map[string]*predictionHistoryEntry)
}

func resetAdaptiveProfileHistoryForTest() {
	globalAdaptiveProfileHistory.mu.Lock()
	defer globalAdaptiveProfileHistory.mu.Unlock()
	globalAdaptiveProfileHistory.entries = make(map[string]*adaptiveProfileEntry)
}

func TestBuildNatObservation(t *testing.T) {
	obs := BuildNatObservation([]ProbeSample{
		{ProbePort: 10206, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "10.0.0.1:10206"},
		{ProbePort: 10207, ObservedAddr: "1.1.1.1:4002", ServerReplyAddr: "10.0.0.2:10207"},
		{ProbePort: 10208, ObservedAddr: "1.1.1.1:4004", ServerReplyAddr: "10.0.0.3:10208"},
	}, true)
	if obs.PublicIP != "1.1.1.1" {
		t.Fatalf("PublicIP = %q, want 1.1.1.1", obs.PublicIP)
	}
	if obs.ObservedBasePort != 4000 {
		t.Fatalf("ObservedBasePort = %d, want 4000", obs.ObservedBasePort)
	}
	if obs.ObservedInterval != 2 {
		t.Fatalf("ObservedInterval = %d, want 2", obs.ObservedInterval)
	}
	if obs.ProbePortRestricted {
		t.Fatal("extra reply should keep ProbePortRestricted=false")
	}
	if obs.ProbeIPCount != 3 {
		t.Fatalf("ProbeIPCount = %d, want 3", obs.ProbeIPCount)
	}
	if obs.MappingConfidenceLow {
		t.Fatal("multi-probe-ip regular samples should not be low confidence")
	}
	if obs.MappingBehavior != NATMappingEndpointDependent || obs.NATType != NATTypeSymmetric {
		t.Fatalf("unexpected nat classification %#v", obs)
	}
}

func TestBuildNatObservationLowConfidence(t *testing.T) {
	obs := BuildNatObservation([]ProbeSample{
		{ProbePort: 10206, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "10.0.0.1:10206"},
	}, false)
	if !obs.ProbePortRestricted {
		t.Fatal("missing extra reply should mark probe port restricted")
	}
	if !obs.MappingConfidenceLow {
		t.Fatal("single sample should stay low confidence")
	}
}

func TestBuildNatObservationSingleProbeIPMultiEndpointStillClassifiesMapping(t *testing.T) {
	obs := BuildNatObservation([]ProbeSample{
		{ProbePort: 10206, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "10.0.0.1:10206"},
		{ProbePort: 10207, ObservedAddr: "1.1.1.1:4002", ServerReplyAddr: "10.0.0.1:10207"},
		{ProbePort: 10208, ObservedAddr: "1.1.1.1:4004", ServerReplyAddr: "10.0.0.1:10208"},
	}, true)
	if obs.ProbeIPCount != 1 {
		t.Fatalf("ProbeIPCount = %d, want 1", obs.ProbeIPCount)
	}
	if obs.ProbeEndpointCount != 3 {
		t.Fatalf("ProbeEndpointCount = %d, want 3", obs.ProbeEndpointCount)
	}
	if obs.MappingConfidenceLow {
		t.Fatalf("single probe ip with multi-endpoint evidence should classify, got %#v", obs)
	}
	if obs.NATType != NATTypeSymmetric || obs.MappingBehavior != NATMappingEndpointDependent {
		t.Fatalf("unexpected nat classification %#v", obs)
	}
	if obs.ClassificationLevel != ClassificationConfidenceMed {
		t.Fatalf("ClassificationLevel = %q, want %q", obs.ClassificationLevel, ClassificationConfidenceMed)
	}
}

func TestBuildNatObservationConflictingSignalsStayLowConfidence(t *testing.T) {
	obs := BuildNatObservation([]ProbeSample{
		{ProbePort: 10206, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "10.0.0.1:10206"},
		{ProbePort: 10207, ObservedAddr: "2.2.2.2:4002", ServerReplyAddr: "10.0.0.2:10207"},
		{ProbePort: 10208, ObservedAddr: "1.1.1.1:4004", ServerReplyAddr: "10.0.0.3:10208"},
	}, false)
	if !obs.ConflictingSignals {
		t.Fatal("multiple observed public IPs should be marked conflicting")
	}
	if !obs.MappingConfidenceLow {
		t.Fatal("conflicting signals should stay low confidence")
	}
}

func TestBuildNatObservationClassifiesRestrictedConeWhenSTUNAndNPSAgree(t *testing.T) {
	obs := BuildNatObservation([]ProbeSample{
		{EndpointID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, ProbePort: 3478, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "198.51.100.10:3478"},
		{EndpointID: "stun-2", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, ProbePort: 3478, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "198.51.100.11:3478"},
		{ProbePort: 10206, Provider: ProbeProviderNPS, Mode: ProbeModeUDP, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "203.0.113.10:10206"},
	}, true)
	if obs.NATType != NATTypeRestrictedCone || obs.MappingBehavior != NATMappingEndpointIndependent || obs.FilteringBehavior != NATFilteringOpen {
		t.Fatalf("unexpected nat classification %#v", obs)
	}
	if obs.MappingConfidenceLow {
		t.Fatalf("restricted cone classification should not stay low confidence %#v", obs)
	}
}

func TestBuildNatObservationClassifiesPortRestrictedWhenMappingStableAndExtraReplyFails(t *testing.T) {
	obs := BuildNatObservation([]ProbeSample{
		{EndpointID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, ProbePort: 3478, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "198.51.100.10:3478"},
		{EndpointID: "stun-2", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, ProbePort: 3478, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "198.51.100.11:3478"},
		{ProbePort: 10206, Provider: ProbeProviderNPS, Mode: ProbeModeUDP, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "203.0.113.10:10206"},
	}, false)
	if obs.NATType != NATTypePortRestricted || obs.FilteringBehavior != NATFilteringPortRestricted {
		t.Fatalf("unexpected nat classification %#v", obs)
	}
}

func TestBuildNatObservationWithoutFilteringProbeKeepsFilteringUnknown(t *testing.T) {
	obs := BuildNatObservationWithEvidence([]ProbeSample{
		{EndpointID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, ProbePort: 3478, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "198.51.100.10:3478"},
		{EndpointID: "stun-2", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, ProbePort: 3478, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "198.51.100.11:3478"},
		{ProbePort: 10206, Provider: ProbeProviderNPS, Mode: ProbeModeUDP, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "203.0.113.10:10206"},
	}, false, false)
	if obs.FilteringTested {
		t.Fatal("filtering should stay untested when extra-reply probe is disabled")
	}
	if obs.FilteringBehavior != NATFilteringUnknown {
		t.Fatalf("FilteringBehavior = %q, want unknown", obs.FilteringBehavior)
	}
	if obs.NATType != NATTypeUnknown {
		t.Fatalf("NATType = %q, want unknown", obs.NATType)
	}
	if obs.ProbePortRestricted {
		t.Fatal("untested filtering should not be forced to port restricted")
	}
}

func TestMergeProbeSamplesPreservesClientReplyAndSTUNSamples(t *testing.T) {
	serverSamples := []ProbeSample{
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10206,
			ObservedAddr:    "1.1.1.1:4000",
			ServerReplyAddr: "0.0.0.0:10206",
		},
	}
	clientSamples := []ProbeSample{
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10206,
			ObservedAddr:    "1.1.1.1:4000",
			ServerReplyAddr: "203.0.113.10:10206",
			ExtraReply:      true,
		},
		{
			EndpointID:      "stun-1",
			Provider:        ProbeProviderSTUN,
			Mode:            ProbeModeBinding,
			ProbePort:       3478,
			ObservedAddr:    "1.1.1.1:4010",
			ServerReplyAddr: "198.51.100.20:3478",
		},
	}
	merged := MergeProbeSamples(serverSamples, clientSamples)
	if len(merged) != 2 {
		t.Fatalf("len(merged) = %d, want 2 (%#v)", len(merged), merged)
	}
	if merged[0].Provider != ProbeProviderNPS || merged[0].ServerReplyAddr != "203.0.113.10:10206" || !merged[0].ExtraReply {
		t.Fatalf("unexpected merged NPS sample %#v", merged[0])
	}
	if merged[1].Provider != ProbeProviderSTUN || merged[1].ObservedAddr != "1.1.1.1:4010" {
		t.Fatalf("unexpected merged STUN sample %#v", merged[1])
	}
	obs := BuildNatObservation(merged, true)
	if obs.ProbeIPCount != 2 {
		t.Fatalf("ProbeIPCount = %d, want 2", obs.ProbeIPCount)
	}
}

func TestMergeProbeSamplesKeepsDistinctNPSReplyIPsOnSameProbePort(t *testing.T) {
	serverSamples := []ProbeSample{
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10206,
			ObservedAddr:    "1.1.1.1:4000",
			ServerReplyAddr: "0.0.0.0:10206",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10207,
			ObservedAddr:    "1.1.1.1:4002",
			ServerReplyAddr: "0.0.0.0:10207",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10208,
			ObservedAddr:    "1.1.1.1:4004",
			ServerReplyAddr: "0.0.0.0:10208",
		},
	}
	clientSamples := []ProbeSample{
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10206,
			ObservedAddr:    "1.1.1.1:4000",
			ServerReplyAddr: "203.0.113.10:10206",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10207,
			ObservedAddr:    "1.1.1.1:4002",
			ServerReplyAddr: "203.0.113.10:10207",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10208,
			ObservedAddr:    "1.1.1.1:4004",
			ServerReplyAddr: "203.0.113.10:10208",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10206,
			ObservedAddr:    "1.1.1.1:4010",
			ServerReplyAddr: "203.0.113.11:10206",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10207,
			ObservedAddr:    "1.1.1.1:4012",
			ServerReplyAddr: "203.0.113.11:10207",
		},
		{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       10208,
			ObservedAddr:    "1.1.1.1:4014",
			ServerReplyAddr: "203.0.113.11:10208",
		},
	}

	merged := MergeProbeSamples(serverSamples, clientSamples)
	if len(merged) != 6 {
		t.Fatalf("len(merged) = %d, want 6 (%#v)", len(merged), merged)
	}
	for _, sample := range merged {
		if strings.HasPrefix(sample.ServerReplyAddr, "0.0.0.0:") {
			t.Fatalf("wildcard server sample should merge into concrete client samples, got %#v", merged)
		}
	}
	obs := BuildNatObservation(merged, true)
	if obs.ProbeIPCount != 2 {
		t.Fatalf("ProbeIPCount = %d, want 2 (%#v)", obs.ProbeIPCount, merged)
	}
	if obs.MappingBehavior != NATMappingEndpointDependent || obs.NATType != NATTypeSymmetric {
		t.Fatalf("unexpected nat classification %#v", obs)
	}
}

func TestNPSProbeKeyIgnoresReplyPortButKeepsReplyIP(t *testing.T) {
	keyA := npsProbeKey(10206, "203.0.113.10:10206")
	keyB := npsProbeKey(10206, "203.0.113.10:49152")
	keyC := npsProbeKey(10206, "203.0.113.11:10206")
	if keyA == "" {
		t.Fatal("expected concrete reply IP to produce a probe key")
	}
	if keyA != keyB {
		t.Fatalf("same reply IP should share the same key: %q vs %q", keyA, keyB)
	}
	if keyA == keyC {
		t.Fatalf("different reply IPs should not share the same key: %q vs %q", keyA, keyC)
	}
	if got := npsProbeKey(10206, "0.0.0.0:10206"); got != "" {
		t.Fatalf("wildcard reply addr should not produce a key, got %q", got)
	}
}

func TestNormalizeProbeEndpoints(t *testing.T) {
	endpoints := NormalizeProbeEndpoints(P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "probe-1", Address: "1.1.1.1:10206"},
			{ID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Address: "stun.example.com:3478"},
		},
	})
	if len(endpoints) != 2 {
		t.Fatalf("len(endpoints) = %d, want 2", len(endpoints))
	}
	if endpoints[0].Provider != ProbeProviderNPS || endpoints[0].Mode != ProbeModeUDP || endpoints[0].Network != ProbeNetworkUDP {
		t.Fatalf("unexpected normalized NPS endpoint %#v", endpoints[0])
	}
	if endpoints[1].Provider != ProbeProviderSTUN || endpoints[1].Mode != ProbeModeBinding || endpoints[1].Network != ProbeNetworkUDP {
		t.Fatalf("unexpected normalized STUN endpoint %#v", endpoints[1])
	}
}

func TestWithDefaultSTUNEndpointsAddsDefaultsOnlyWhenMissing(t *testing.T) {
	probe := P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "probe-1", Address: "1.1.1.1:10206"},
		},
	}
	withDefaults := WithDefaultSTUNEndpoints(probe, []string{"stun.example.com:3478", "stun2.example.com:3478"})
	if len(withDefaults.Endpoints) != 3 {
		t.Fatalf("len(withDefaults.Endpoints) = %d, want 3", len(withDefaults.Endpoints))
	}
	if !HasProbeProvider(withDefaults, ProbeProviderSTUN) {
		t.Fatal("expected default STUN endpoints to be appended")
	}
	serverProvided := WithDefaultSTUNEndpoints(P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "probe-1", Address: "1.1.1.1:10206"},
			{ID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Network: ProbeNetworkUDP, Address: "stun.server:3478"},
		},
	}, []string{"stun.default:3478"})
	if len(serverProvided.Endpoints) != 2 {
		t.Fatalf("server-provided STUN list should stay unchanged, got %#v", serverProvided.Endpoints)
	}
}

func TestHasUsableProbeEndpointRequiresSupportedTransport(t *testing.T) {
	if !HasUsableProbeEndpoint(P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "probe-1", Address: "1.1.1.1:10206"},
		},
	}) {
		t.Fatal("supported NPS UDP probe endpoint should be usable")
	}
	if HasUsableProbeEndpoint(P2PProbeConfig{
		Endpoints: []P2PProbeEndpoint{
			{ID: "probe-1", Provider: ProbeProviderNPS, Mode: ProbeModeBinding, Network: ProbeNetworkUDP, Address: "1.1.1.1:10206"},
			{ID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Network: "tcp", Address: "stun.example.com:3478"},
		},
	}) {
		t.Fatal("unsupported probe endpoint transport should not be treated as usable")
	}
}

func TestSelectPunchPlanPredictionDefaults(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}},
		P2PPeerInfo{Nat: NatObservation{ObservedBasePort: 5000, ObservedInterval: 0}},
		DefaultTimeouts(),
	)
	if !plan.EnablePrediction {
		t.Fatal("restricted/low-confidence observation should enable prediction")
	}
	if !plan.UseTargetSpray {
		t.Fatal("default main path should use target spray")
	}
	if plan.UseBirthdayAttack {
		t.Fatal("birthday attack must stay disabled by default")
	}
	if plan.AllowBirthdayFallback {
		t.Fatal("single-sided hard NAT should stay on the default target-spray main path")
	}
	if len(plan.PredictionIntervals) == 0 || plan.PredictionIntervals[0] != DefaultPredictionInterval {
		t.Fatalf("unexpected PredictionIntervals %#v", plan.PredictionIntervals)
	}
	if plan.PredictionInterval != DefaultPredictionInterval {
		t.Fatalf("PredictionInterval = %d, want %d", plan.PredictionInterval, DefaultPredictionInterval)
	}
	if plan.HandshakeTimeout != 20*time.Second {
		t.Fatalf("HandshakeTimeout = %s, want 20s", plan.HandshakeTimeout)
	}
}

func TestPunchPlanNominationTimingCapsToHandshakeTimeout(t *testing.T) {
	plan := PunchPlan{
		HandshakeTimeout:        300 * time.Millisecond,
		NominationDelay:         120 * time.Millisecond,
		NominationRetryInterval: 300 * time.Millisecond,
	}
	if got := plan.nominationDelay(); got != 50*time.Millisecond {
		t.Fatalf("nominationDelay() = %s, want %s", got, 50*time.Millisecond)
	}
	if got := plan.nominationRetryInterval(); got != 60*time.Millisecond {
		t.Fatalf("nominationRetryInterval() = %s, want %s", got, 60*time.Millisecond)
	}
	if got := plan.renominationTimeout(); got != 75*time.Millisecond {
		t.Fatalf("renominationTimeout() = %s, want %s", got, 75*time.Millisecond)
	}
	if got := plan.renominationCooldown(); got != 60*time.Millisecond {
		t.Fatalf("renominationCooldown() = %s, want %s", got, 60*time.Millisecond)
	}
}

func TestSelectPunchPlanSingleProbeIPMultiEndpointStillTriggersPrediction(t *testing.T) {
	self := P2PPeerInfo{Nat: BuildNatObservation([]ProbeSample{
		{ProbePort: 10206, ObservedAddr: "1.1.1.1:4000", ServerReplyAddr: "10.0.0.1:10206"},
		{ProbePort: 10207, ObservedAddr: "1.1.1.1:4002", ServerReplyAddr: "10.0.0.1:10207"},
		{ProbePort: 10208, ObservedAddr: "1.1.1.1:4004", ServerReplyAddr: "10.0.0.1:10208"},
	}, true)}
	peer := P2PPeerInfo{Nat: NatObservation{ObservedBasePort: 5000, ObservedInterval: 2}}
	plan := SelectPunchPlan(self, peer, DefaultTimeouts())
	if self.Nat.MappingConfidenceLow {
		t.Fatalf("single probe ip should now classify from multi-endpoint evidence: %#v", self.Nat)
	}
	if self.Nat.NATType != NATTypeSymmetric {
		t.Fatalf("NATType = %q, want %q", self.Nat.NATType, NATTypeSymmetric)
	}
	if !plan.EnablePrediction || !plan.UseTargetSpray {
		t.Fatalf("unexpected plan %#v", plan)
	}
	if len(plan.PredictionIntervals) == 0 {
		t.Fatal("prediction should build interval candidates")
	}
}

func TestSelectPunchPlanAllowsBirthdayFallbackForHardPeers(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}},
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true, ObservedBasePort: 5000}},
		DefaultTimeouts(),
	)
	if !plan.AllowBirthdayFallback {
		t.Fatal("dual hard/unknown peers should allow birthday fallback after target spray failure")
	}
	if plan.UseBirthdayAttack {
		t.Fatal("birthday attack must still be off until the target-spray path fails")
	}
}

func TestSelectPunchPlanEnablesPredictionForClassifiedSymmetricPeer(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{NATType: NATTypeSymmetric, MappingBehavior: NATMappingEndpointDependent}},
		P2PPeerInfo{Nat: NatObservation{ObservedBasePort: 5000, NATType: NATTypeRestrictedCone}},
		DefaultTimeouts(),
	)
	if !plan.EnablePrediction || !plan.UseTargetSpray {
		t.Fatalf("classified symmetric nat should still enable prediction, got %#v", plan)
	}
}

func TestSelectPunchPlanKeepsBirthdayFallbackDisabledForLoosePeers(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{ObservedBasePort: 5000, ObservedInterval: 2}},
		P2PPeerInfo{Nat: NatObservation{ObservedBasePort: 6000, ObservedInterval: 2}},
		DefaultTimeouts(),
	)
	if plan.AllowBirthdayFallback {
		t.Fatal("loose peers should not enable birthday fallback")
	}
	if plan.UseBirthdayAttack {
		t.Fatal("birthday attack must not be enabled directly by default")
	}
}

func TestSelectPunchPlanTreatsUnknownFilteringAsConservative(t *testing.T) {
	self := P2PPeerInfo{Nat: NatObservation{
		ObservedBasePort:    5000,
		ProbeEndpointCount:  3,
		MappingBehavior:     NATMappingEndpointIndependent,
		NATType:             NATTypeUnknown,
		ClassificationLevel: ClassificationConfidenceLow,
		Samples: []ProbeSample{
			{ProbePort: 10206, ObservedAddr: "1.1.1.1:5000", ServerReplyAddr: "203.0.113.10:10206"},
			{ProbePort: 10207, ObservedAddr: "1.1.1.1:5000", ServerReplyAddr: "203.0.113.10:10207"},
			{ProbePort: 10208, ObservedAddr: "1.1.1.1:5000", ServerReplyAddr: "203.0.113.10:10208"},
		},
	}}
	peer := P2PPeerInfo{Nat: NatObservation{
		ObservedBasePort:    6000,
		ProbeEndpointCount:  3,
		MappingBehavior:     NATMappingEndpointIndependent,
		NATType:             NATTypeUnknown,
		ClassificationLevel: ClassificationConfidenceLow,
		Samples: []ProbeSample{
			{ProbePort: 10206, ObservedAddr: "2.2.2.2:6000", ServerReplyAddr: "203.0.113.20:10206"},
			{ProbePort: 10207, ObservedAddr: "2.2.2.2:6000", ServerReplyAddr: "203.0.113.20:10207"},
			{ProbePort: 10208, ObservedAddr: "2.2.2.2:6000", ServerReplyAddr: "203.0.113.20:10208"},
		},
	}}
	plan := SelectPunchPlan(self, peer, DefaultTimeouts())
	if !plan.EnablePrediction {
		t.Fatalf("unknown filtering should keep prediction enabled, got %#v", plan)
	}
	if !plan.AllowBirthdayFallback {
		t.Fatalf("unknown filtering on both peers should keep conservative fallback enabled, got %#v", plan)
	}
}

func TestSelectPunchPlanTunesEasyPeersForLowerSprayBudget(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, Samples: []ProbeSample{{ObservedAddr: "1.1.1.1:5000"}}}},
		P2PPeerInfo{Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, ObservedBasePort: 6000, Samples: []ProbeSample{{ObservedAddr: "2.2.2.2:6000"}}}},
		DefaultTimeouts(),
	)
	if plan.EnablePrediction || plan.UseTargetSpray {
		t.Fatalf("easy peers should stay on the light direct path, got %#v", plan)
	}
	if plan.SprayRounds != 1 || plan.SprayBurst != 4 {
		t.Fatalf("easy peers should reduce spray budget, got %#v", plan)
	}
	if plan.SprayPerPacketSleep != 5*time.Millisecond {
		t.Fatalf("easy peers should respect the paced spray floor, got %#v", plan)
	}
	if plan.NominationDelay != 80*time.Millisecond || plan.NominationRetryInterval != 180*time.Millisecond {
		t.Fatalf("easy peers should use faster nomination timing, got %#v", plan)
	}
}

func TestSelectPunchPlanKeepsPredictionForLowConfidenceNPSOnlyEvidence(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{
			PublicIP:            "1.1.1.1",
			ObservedBasePort:    5000,
			MappingBehavior:     NATMappingEndpointIndependent,
			FilteringBehavior:   NATFilteringOpen,
			NATType:             NATTypeRestrictedCone,
			ClassificationLevel: ClassificationConfidenceLow,
			Samples: []ProbeSample{
				{Provider: ProbeProviderNPS, ProbePort: 10206, ObservedAddr: "1.1.1.1:5000", ServerReplyAddr: "203.0.113.10:10206"},
				{Provider: ProbeProviderNPS, ProbePort: 10207, ObservedAddr: "1.1.1.1:5000", ServerReplyAddr: "203.0.113.10:10207"},
			},
		}},
		P2PPeerInfo{Nat: NatObservation{
			PublicIP:            "2.2.2.2",
			ObservedBasePort:    6000,
			MappingBehavior:     NATMappingEndpointIndependent,
			FilteringBehavior:   NATFilteringOpen,
			NATType:             NATTypeRestrictedCone,
			ClassificationLevel: ClassificationConfidenceLow,
			Samples: []ProbeSample{
				{Provider: ProbeProviderNPS, ProbePort: 10206, ObservedAddr: "2.2.2.2:6000", ServerReplyAddr: "203.0.113.20:10206"},
				{Provider: ProbeProviderNPS, ProbePort: 10207, ObservedAddr: "2.2.2.2:6000", ServerReplyAddr: "203.0.113.20:10207"},
			},
		}},
		DefaultTimeouts(),
	)
	if !plan.EnablePrediction || !plan.UseTargetSpray {
		t.Fatalf("low-confidence NPS-only evidence should keep conservative prediction enabled, got %#v", plan)
	}
}

func TestSelectPunchPlanTunesHardPeersForHigherSprayBudget(t *testing.T) {
	plan := SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{NATType: NATTypeSymmetric, ProbePortRestricted: true, MappingConfidenceLow: true}},
		P2PPeerInfo{Nat: NatObservation{NATType: NATTypeSymmetric, ProbePortRestricted: true, MappingConfidenceLow: true, ObservedBasePort: 6000}},
		DefaultTimeouts(),
	)
	if !plan.AllowBirthdayFallback || !plan.EnablePrediction {
		t.Fatalf("hard peers should keep the hard path enabled, got %#v", plan)
	}
	if plan.SprayRounds != 3 || plan.SprayBurst != 10 {
		t.Fatalf("hard peers should increase spray budget, got %#v", plan)
	}
	if plan.SprayPerPacketSleep != 5*time.Millisecond {
		t.Fatalf("hard peers should keep the paced spray floor, got %#v", plan)
	}
}

func TestApplyProbePlanOptionsRespectsBirthdayDefaultOff(t *testing.T) {
	plan := ApplyProbePlanOptions(SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}},
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}},
		DefaultTimeouts(),
	), P2PProbeConfig{
		Options: map[string]string{
			"enable_birthday_attack": "false",
		},
	}, P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}}, P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}})
	if plan.AllowBirthdayFallback {
		t.Fatal("birthday fallback should stay disabled when config option is false")
	}
}

func TestApplyProbePlanOptionsOverridesSprayConfig(t *testing.T) {
	plan := ApplyProbePlanOptions(SelectPunchPlan(
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}},
		P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}},
		DefaultTimeouts(),
	), P2PProbeConfig{
		Options: map[string]string{
			"enable_target_spray":          "false",
			"enable_birthday_attack":       "true",
			"default_prediction_interval":  "3",
			"target_spray_span":            "12",
			"target_spray_rounds":          "4",
			"target_spray_burst":           "2",
			"target_spray_packet_sleep_ms": "7",
			"target_spray_burst_gap_ms":    "11",
			"target_spray_phase_gap_ms":    "13",
			"birthday_listen_ports":        "6",
			"birthday_targets_per_port":    "9",
		},
	}, P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}}, P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true, MappingConfidenceLow: true}})
	if plan.UseTargetSpray {
		t.Fatal("enable_target_spray=false should disable target spray")
	}
	if !plan.AllowBirthdayFallback {
		t.Fatal("enable_birthday_attack=true should preserve birthday fallback availability")
	}
	if plan.PredictionInterval != 3 || plan.SpraySpan != 12 || plan.SprayRounds != 4 || plan.SprayBurst != 2 {
		t.Fatalf("unexpected spray config %#v", plan)
	}
	if plan.SprayPerPacketSleep != 7*time.Millisecond || plan.SprayBurstGap != 11*time.Millisecond || plan.SprayPhaseGap != 13*time.Millisecond {
		t.Fatalf("unexpected spray timings %#v", plan)
	}
	if plan.BirthdayListenPorts != 6 || plan.BirthdayTargetsPerPort != 9 {
		t.Fatalf("unexpected birthday config %#v", plan)
	}
}

func TestApplyProbePlanOptionsKeepsBirthdayFallbackForSymmetricPeersWhenEnabled(t *testing.T) {
	self := P2PPeerInfo{Nat: NatObservation{NATType: NATTypeSymmetric, MappingBehavior: NATMappingEndpointDependent}}
	peer := P2PPeerInfo{Nat: NatObservation{NATType: NATTypeSymmetric, MappingBehavior: NATMappingEndpointDependent, ObservedBasePort: 5000}}
	plan := ApplyProbePlanOptions(SelectPunchPlan(self, peer, DefaultTimeouts()), P2PProbeConfig{
		Options: map[string]string{
			"enable_birthday_attack": "true",
		},
	}, self, peer)
	if !plan.AllowBirthdayFallback {
		t.Fatal("symmetric peers should keep birthday fallback when config enables it")
	}
	if plan.UseBirthdayAttack {
		t.Fatal("birthday attack should still wait for target spray failure before enabling")
	}
}

func TestBuildPredictionIntervals(t *testing.T) {
	intervals := BuildPredictionIntervals(NatObservation{
		ObservedInterval: 4,
		Samples: []ProbeSample{
			{ObservedAddr: "1.1.1.1:4000"},
			{ObservedAddr: "1.1.1.1:4004"},
			{ObservedAddr: "1.1.1.1:4008"},
		},
	}, true, true)
	if len(intervals) < 3 {
		t.Fatalf("expected multiple intervals, got %#v", intervals)
	}
	if intervals[0] != 4 {
		t.Fatalf("primary interval = %d, want 4", intervals[0])
	}
	foundOne := false
	for _, interval := range intervals {
		if interval == 1 {
			foundOne = true
			break
		}
	}
	if !foundOne {
		t.Fatalf("interval candidates should include normalized fallback 1, got %#v", intervals)
	}
}

func TestApplyProbePlanOptionsCanDisableForcedPrediction(t *testing.T) {
	self := P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: true}}
	peer := P2PPeerInfo{Nat: NatObservation{ProbePortRestricted: false, Samples: []ProbeSample{{ObservedAddr: "1.1.1.1:5000"}}}}
	plan := ApplyProbePlanOptions(SelectPunchPlan(self, peer, DefaultTimeouts()), P2PProbeConfig{
		Options: map[string]string{
			"force_predict_on_restricted": "false",
		},
	}, self, peer)
	if plan.EnablePrediction {
		t.Fatal("force_predict_on_restricted=false should disable prediction when low confidence is absent")
	}
	if plan.UseTargetSpray {
		t.Fatal("target spray should be disabled when forced prediction is turned off and peer samples exist")
	}
}

func TestApplySummaryHintsToPlanDualStackStrongEvidence(t *testing.T) {
	plan := PunchPlan{
		HandshakeTimeout:        2 * time.Second,
		NominationDelay:         80 * time.Millisecond,
		NominationRetryInterval: 300 * time.Millisecond,
		SprayRounds:             2,
		SprayBurst:              8,
	}
	summary := P2PProbeSummary{
		Self: P2PPeerInfo{Nat: NatObservation{
			NATType:             NATTypeRestrictedCone,
			MappingBehavior:     NATMappingEndpointIndependent,
			FilteringBehavior:   NATFilteringOpen,
			FilteringTested:     true,
			ClassificationLevel: ClassificationConfidenceHigh,
			Samples: []ProbeSample{
				{Provider: ProbeProviderNPS, ObservedAddr: "1.1.1.1:5000"},
				{Provider: ProbeProviderSTUN, ObservedAddr: "1.1.1.1:5000"},
			},
		}},
		Peer: P2PPeerInfo{Nat: NatObservation{
			NATType:             NATTypeRestrictedCone,
			MappingBehavior:     NATMappingEndpointIndependent,
			FilteringBehavior:   NATFilteringOpen,
			FilteringTested:     true,
			ClassificationLevel: ClassificationConfidenceHigh,
			Samples: []ProbeSample{
				{Provider: ProbeProviderNPS, ObservedAddr: "2.2.2.2:6000"},
				{Provider: ProbeProviderSTUN, ObservedAddr: "2.2.2.2:6000"},
			},
		}},
		Hints: map[string]any{
			"shared_family_count": 2,
		},
	}
	tuned := ApplySummaryHintsToPlan(plan, summary)
	if tuned.SprayRounds != 1 || tuned.SprayBurst != 5 {
		t.Fatalf("ApplySummaryHintsToPlan() spray budget = (%d,%d), want (1,5)", tuned.SprayRounds, tuned.SprayBurst)
	}
	if tuned.NominationDelay != 100*time.Millisecond {
		t.Fatalf("ApplySummaryHintsToPlan() nomination delay = %s, want 100ms", tuned.NominationDelay)
	}
	if tuned.NominationRetryInterval != 220*time.Millisecond {
		t.Fatalf("ApplySummaryHintsToPlan() nomination retry = %s, want 220ms", tuned.NominationRetryInterval)
	}
}

func TestApplySummaryHintsToPlanUsesAdaptiveProfileHistory(t *testing.T) {
	resetAdaptiveProfileHistoryForTest()
	t.Cleanup(resetAdaptiveProfileHistoryForTest)

	summary := P2PProbeSummary{
		Self: P2PPeerInfo{Nat: NatObservation{
			NATType:             NATTypeRestrictedCone,
			MappingBehavior:     NATMappingEndpointIndependent,
			FilteringBehavior:   NATFilteringOpen,
			FilteringTested:     true,
			ClassificationLevel: ClassificationConfidenceMed,
			Samples: []ProbeSample{
				{Provider: ProbeProviderNPS, ObservedAddr: "1.1.1.1:5000"},
			},
		}},
		Peer: P2PPeerInfo{Nat: NatObservation{
			NATType:             NATTypeRestrictedCone,
			MappingBehavior:     NATMappingEndpointIndependent,
			FilteringBehavior:   NATFilteringOpen,
			FilteringTested:     true,
			ClassificationLevel: ClassificationConfidenceMed,
			ObservedBasePort:    6000,
			Samples: []ProbeSample{
				{Provider: ProbeProviderNPS, ObservedAddr: "2.2.2.2:6000"},
			},
		}},
	}
	recordAdaptiveProfileSuccess(summary, common.CONN_KCP)
	recordAdaptiveProfileSuccess(summary, common.CONN_KCP)

	plan := PunchPlan{
		HandshakeTimeout:        2 * time.Second,
		NominationDelay:         120 * time.Millisecond,
		NominationRetryInterval: 300 * time.Millisecond,
		SprayRounds:             2,
		SprayBurst:              8,
	}
	tuned := ApplySummaryHintsToPlan(plan, summary)
	if tuned.SprayRounds != 1 || tuned.SprayBurst != 7 {
		t.Fatalf("adaptive history should lighten plan, got rounds=%d burst=%d", tuned.SprayRounds, tuned.SprayBurst)
	}
	if tuned.NominationDelay != 105*time.Millisecond || tuned.NominationRetryInterval != 200*time.Millisecond {
		t.Fatalf("adaptive history should tighten nomination timing, got delay=%s retry=%s", tuned.NominationDelay, tuned.NominationRetryInterval)
	}
}

func TestAdaptiveProfileTimeoutReducesScore(t *testing.T) {
	resetAdaptiveProfileHistoryForTest()
	t.Cleanup(resetAdaptiveProfileHistoryForTest)

	summary := P2PProbeSummary{
		Self: P2PPeerInfo{Families: []P2PFamilyInfo{{Family: "udp4", Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, FilteringTested: true, ClassificationLevel: ClassificationConfidenceMed}}}},
		Peer: P2PPeerInfo{Families: []P2PFamilyInfo{{Family: "udp4", Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, FilteringTested: true, ClassificationLevel: ClassificationConfidenceMed}}}},
	}
	recordAdaptiveProfileSuccess(summary, common.CONN_KCP)
	before := adaptiveProfileScore(summary)
	recordAdaptiveProfileTimeout(summary)
	after := adaptiveProfileScore(summary)
	if after >= before {
		t.Fatalf("adaptiveProfileScore() should drop after timeout, before=%d after=%d", before, after)
	}
}

func TestSortRuntimeFamilyWorkersPrefersAdaptiveProfileScore(t *testing.T) {
	resetAdaptiveProfileHistoryForTest()
	t.Cleanup(resetAdaptiveProfileHistoryForTest)

	summary4 := P2PProbeSummary{
		Self: P2PPeerInfo{Families: []P2PFamilyInfo{{Family: "udp4", Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, FilteringTested: true, ClassificationLevel: ClassificationConfidenceMed}}}},
		Peer: P2PPeerInfo{Families: []P2PFamilyInfo{{Family: "udp4", Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, FilteringTested: true, ClassificationLevel: ClassificationConfidenceMed, ObservedBasePort: 6000}}}},
	}
	summary6 := P2PProbeSummary{
		Self: P2PPeerInfo{Families: []P2PFamilyInfo{{Family: "udp6", Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, FilteringTested: true, ClassificationLevel: ClassificationConfidenceMed}}}},
		Peer: P2PPeerInfo{Families: []P2PFamilyInfo{{Family: "udp6", Nat: NatObservation{NATType: NATTypeRestrictedCone, MappingBehavior: NATMappingEndpointIndependent, FilteringBehavior: NATFilteringOpen, FilteringTested: true, ClassificationLevel: ClassificationConfidenceMed, ObservedBasePort: 7000}}}},
	}
	recordAdaptiveProfileSuccess(summary6, common.CONN_KCP)
	recordAdaptiveProfileSuccess(summary6, common.CONN_KCP)

	workers := []*runtimeFamilyWorker{
		{family: udpFamilyV4, rs: &runtimeSession{}, summary: summary4},
		{family: udpFamilyV6, rs: &runtimeSession{}, summary: summary6},
	}
	sortRuntimeFamilyWorkers(workers)
	if workers[0].family != udpFamilyV6 {
		t.Fatalf("sortRuntimeFamilyWorkers() should prefer adaptive success family, got first=%s", workers[0].family.String())
	}
}

func TestBuildTargetSprayPorts(t *testing.T) {
	ports := BuildTargetSprayPorts(5000, 2, 6)
	wantHead := []int{5000, 5002, 4998}
	for i, want := range wantHead {
		if ports[i] != want {
			t.Fatalf("ports[%d] = %d, want %d (%#v)", i, ports[i], want, ports)
		}
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			t.Fatalf("invalid port %d in %#v", port, ports)
		}
	}
}

func TestBuildTargetSprayPortsNormalizesInterval(t *testing.T) {
	ports := BuildTargetSprayPorts(10, 0, 4)
	if len(ports) != 4 {
		t.Fatalf("len(ports) = %d, want 4", len(ports))
	}
	if ports[0] != 10 || ports[1] != 11 || ports[2] != 9 {
		t.Fatalf("unexpected interval-normalized result %#v", ports)
	}
}

func TestBuildTargetSprayPortsMulti(t *testing.T) {
	ports := BuildTargetSprayPortsMulti(5000, []int{4, 2, 1}, 8)
	if len(ports) != 8 {
		t.Fatalf("len(ports) = %d, want 8 (%#v)", len(ports), ports)
	}
	if ports[0] != 5000 {
		t.Fatalf("ports[0] = %d, want 5000", ports[0])
	}
	expected := map[int]bool{5004: false, 4996: false, 5002: false, 4998: false}
	for _, port := range ports {
		if _, ok := expected[port]; ok {
			expected[port] = true
		}
	}
	for port, seen := range expected {
		if !seen {
			t.Fatalf("expected multi-interval spray to include %d in %#v", port, ports)
		}
	}
}

func TestBuildPunchTargetsFiltersAndDedupes(t *testing.T) {
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
				{ObservedAddr: "1.1.1.1:5002"},
			},
		},
		LocalAddrs: []string{
			"192.168.0.2:5000",
			"[2001:db8::1]:5000",
			"192.168.0.2:5000",
		},
	}
	targets := BuildPunchTargets(peer, PunchPlan{
		PredictionInterval: 2,
		SpraySpan:          6,
	})
	if len(targets) == 0 {
		t.Fatal("expected punch targets")
	}
	for _, target := range targets {
		if target == "[2001:db8::1]:5000" {
			t.Fatalf("ipv6 local addr should be filtered for ipv4 peer: %#v", targets)
		}
	}
	if targets[0] != "1.1.1.1:5000" {
		t.Fatalf("first target = %q, want first observed addr", targets[0])
	}
}

func TestBuildDirectPunchTargetsFiltersAndDedupes(t *testing.T) {
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP: "1.1.1.1",
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{
			"192.168.0.2:5000",
			"[2001:db8::1]:5000",
			"192.168.0.2:5000",
		},
	}
	targets := BuildDirectPunchTargets(peer)
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2 (%#v)", len(targets), targets)
	}
	if targets[0] != "1.1.1.1:5000" || targets[1] != "192.168.0.2:5000" {
		t.Fatalf("unexpected direct targets %#v", targets)
	}
}

func TestBuildDirectPunchTargetsPrefersPortMapping(t *testing.T) {
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PortMapping: &PortMappingInfo{ExternalAddr: "2.2.2.2:6000"},
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{"192.168.0.2:5000"},
	}
	targets := BuildDirectPunchTargets(peer)
	if len(targets) == 0 || targets[0] != "2.2.2.2:6000" {
		t.Fatalf("port mapping target should be first, got %#v", targets)
	}
}

func TestBuildPreferredDirectPunchTargetsPrefersMatchingPeerLocalAddr(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{
			"192.168.0.10:4000",
		},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PortMapping: &PortMappingInfo{ExternalAddr: "2.2.2.2:6000"},
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{
			"192.168.0.20:5000",
			"[2001:db8::20]:5000",
		},
	}
	targets := BuildPreferredDirectPunchTargets(self, peer)
	if len(targets) == 0 {
		t.Fatal("expected preferred direct targets")
	}
	if targets[0] != "192.168.0.20:5000" {
		t.Fatalf("first preferred direct target = %q, want peer ipv4 local addr (%#v)", targets[0], targets)
	}
	for _, target := range targets {
		if target == "[2001:db8::20]:5000" {
			t.Fatalf("ipv6 peer local addr should be skipped when self only supports ipv4: %#v", targets)
		}
	}
}

func TestBuildPreferredDirectPunchTargetsDoesNotPrioritizeForeignPrivateSubnet(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{
			"10.0.0.10:4000",
		},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PortMapping: &PortMappingInfo{ExternalAddr: "2.2.2.2:6000"},
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{
			"192.168.0.20:5000",
		},
	}
	targets := BuildPreferredDirectPunchTargets(self, peer)
	if len(targets) < 2 {
		t.Fatalf("expected preferred direct targets, got %#v", targets)
	}
	if targets[0] != "2.2.2.2:6000" {
		t.Fatalf("foreign private subnet should not outrank public candidates, got %#v", targets)
	}
}

func TestBuildPreferredPunchTargetsKeepsDirectCandidatesBeforePrediction(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{"192.168.0.10:4000"},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{"192.168.0.20:5000"},
	}
	targets := BuildPreferredPunchTargets(self, peer, PunchPlan{
		PredictionIntervals: []int{2},
		SpraySpan:           6,
	})
	if len(targets) < 3 {
		t.Fatalf("expected enough targets, got %#v", targets)
	}
	if targets[0] != "192.168.0.20:5000" {
		t.Fatalf("first target = %q, want direct local addr first (%#v)", targets[0], targets)
	}
	if targets[1] != "1.1.1.1:5000" {
		t.Fatalf("second target = %q, want observed addr second (%#v)", targets[1], targets)
	}
}

func TestBuildPreferredPunchTargetsDefersForeignPrivateLocalFallback(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{"10.0.0.10:4000"},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{"192.168.0.20:5000"},
	}
	targets := BuildPreferredPunchTargets(self, peer, PunchPlan{
		PredictionIntervals: []int{2},
		SpraySpan:           4,
	})
	if len(targets) < 3 {
		t.Fatalf("expected enough targets, got %#v", targets)
	}
	if targets[0] != "1.1.1.1:5000" {
		t.Fatalf("first target = %q, want observed public target first (%#v)", targets[0], targets)
	}
	if targets[len(targets)-1] != "192.168.0.20:5000" {
		t.Fatalf("foreign private local addr should be deferred to the end, got %#v", targets)
	}
}

func TestBuildPreferredPunchTargetsUsesPredictionHistoryBeforeDefaultSpray(t *testing.T) {
	resetPredictionHistoryForTest()
	t.Cleanup(resetPredictionHistoryForTest)

	self := P2PPeerInfo{
		LocalAddrs: []string{"192.168.0.10:4000"},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			NATType:          NATTypeSymmetric,
			MappingBehavior:  NATMappingEndpointDependent,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
	}
	recordPredictionSuccess(peer.Nat, "1.1.1.1:5006")
	recordPredictionSuccess(peer.Nat, "1.1.1.1:5006")
	recordPredictionSuccess(peer.Nat, "1.1.1.1:5008")

	targets := BuildPreferredPunchTargets(self, peer, PunchPlan{
		PredictionIntervals: []int{2},
		SpraySpan:           8,
	})
	if len(targets) < 3 {
		t.Fatalf("expected enough targets, got %#v", targets)
	}
	if targets[0] != "1.1.1.1:5000" {
		t.Fatalf("first target = %q, want observed addr first (%#v)", targets[0], targets)
	}
	if targets[1] != "1.1.1.1:5006" {
		t.Fatalf("second target = %q, want historical offset first (%#v)", targets[1], targets)
	}
}

func TestCandidateRankerKeepsForeignPrivateFallbackBelowPublicFallback(t *testing.T) {
	ranker := NewCandidateRanker(
		P2PPeerInfo{LocalAddrs: []string{"192.168.1.10:4000"}},
		P2PPeerInfo{Nat: NatObservation{PublicIP: "203.0.113.10", ObservedBasePort: 5000}},
		PunchPlan{},
	)
	publicFallback := ranker.Priority("", "203.0.113.10:5002")
	foreignPrivate := ranker.Priority("", "10.0.0.5:6000")
	sameSubnetPrivate := ranker.Priority("", "192.168.1.20:6000")
	if foreignPrivate.Score >= publicFallback.Score {
		t.Fatalf("foreign private fallback should stay below public fallback: private=%#v public=%#v", foreignPrivate, publicFallback)
	}
	if sameSubnetPrivate.Score <= foreignPrivate.Score {
		t.Fatalf("same-subnet private fallback should outrank foreign private fallback: same=%#v foreign=%#v", sameSubnetPrivate, foreignPrivate)
	}
}

func TestCandidateRankerReusesPreferredTargetPlans(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{"192.168.0.10:4000"},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
		LocalAddrs: []string{"192.168.0.20:5000"},
	}
	plan := PunchPlan{
		UseTargetSpray:         true,
		AllowBirthdayFallback:  true,
		PredictionIntervals:    []int{2},
		SpraySpan:              6,
		BirthdayTargetsPerPort: 4,
	}
	ranker := NewCandidateRanker(self, peer, plan)
	if !reflect.DeepEqual(ranker.DirectTargets(), BuildPreferredDirectPunchTargets(self, peer)) {
		t.Fatalf("direct targets diverged: got %#v want %#v", ranker.DirectTargets(), BuildPreferredDirectPunchTargets(self, peer))
	}
	if !reflect.DeepEqual(ranker.PrimaryTargets(true), BuildPreferredPunchTargets(self, peer, plan)) {
		t.Fatalf("primary targets diverged: got %#v want %#v", ranker.PrimaryTargets(true), BuildPreferredPunchTargets(self, peer, plan))
	}
	if !reflect.DeepEqual(ranker.BirthdayTargets(), BuildBirthdayPunchTargets(peer, plan)) {
		t.Fatalf("birthday targets diverged: got %#v want %#v", ranker.BirthdayTargets(), BuildBirthdayPunchTargets(peer, plan))
	}
}

func TestCandidateRankerTargetOnlyTargetsExcludeDirectSet(t *testing.T) {
	self := P2PPeerInfo{LocalAddrs: []string{"192.168.0.10:4000"}}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			Samples:          []ProbeSample{{ObservedAddr: "1.1.1.1:5000"}},
		},
	}
	ranker := NewCandidateRanker(self, peer, PunchPlan{
		UseTargetSpray:      true,
		PredictionIntervals: []int{2},
		SpraySpan:           6,
	})
	direct := ranker.DirectTargets()
	targetOnly := ranker.TargetOnlyTargets()
	for _, directAddr := range direct {
		for _, targetAddr := range targetOnly {
			if directAddr == targetAddr {
				t.Fatalf("target-only targets should exclude direct target %q", directAddr)
			}
		}
	}
	if len(targetOnly) == 0 {
		t.Fatal("target-only targets should preserve prediction addresses")
	}
}

func TestCandidateRankerTargetStagesPreferLikelyNextOnSequentialMappings(t *testing.T) {
	self := P2PPeerInfo{LocalAddrs: []string{"192.168.0.10:4000"}}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			MappingBehavior:  NATMappingEndpointDependent,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
				{ObservedAddr: "1.1.1.1:5002"},
				{ObservedAddr: "1.1.1.1:5004"},
			},
		},
	}
	ranker := NewCandidateRanker(self, peer, PunchPlan{
		UseTargetSpray:      true,
		PredictionIntervals: []int{2},
		SpraySpan:           6,
	})
	stages := ranker.TargetStages()
	if len(stages) == 0 {
		t.Fatal("target stages should be available")
	}
	if stages[0].Name != "target_likely_next" {
		t.Fatalf("first target stage = %q, want target_likely_next", stages[0].Name)
	}
	if len(stages[0].Targets) == 0 || stages[0].Targets[0] != "1.1.1.1:5006" {
		t.Fatalf("likely-next stage should lead with the next sequential port, got %#v", stages[0].Targets)
	}
}

func TestCandidateRankerResponsivePriorityPromotesAuthenticatedPublicCandidate(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{"192.168.0.10:4000"},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
	}
	ranker := NewCandidateRanker(self, peer, PunchPlan{UseTargetSpray: true})
	staticPriority := ranker.Priority("", "1.1.1.1:5012")
	responsivePriority := ranker.ResponsivePriority("1.1.1.1:5012")
	if responsivePriority.Score <= staticPriority.Score {
		t.Fatalf("responsive candidate should outrank static fallback: responsive=%#v static=%#v", responsivePriority, staticPriority)
	}
	if responsivePriority.Reason != "responsive_public(delta=12)" {
		t.Fatalf("responsive reason = %q, want responsive_public(delta=12)", responsivePriority.Reason)
	}
}

func TestCandidateRankerResponsivePriorityPrefersSameSubnetLocalCandidate(t *testing.T) {
	self := P2PPeerInfo{
		LocalAddrs: []string{"192.168.0.10:4000"},
	}
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
		},
	}
	ranker := NewCandidateRanker(self, peer, PunchPlan{})
	sameSubnet := ranker.ResponsivePriority("192.168.0.20:5000")
	public := ranker.ResponsivePriority("1.1.1.1:5000")
	if sameSubnet.Score <= public.Score {
		t.Fatalf("same subnet responsive candidate should outrank public responsive candidate: same=%#v public=%#v", sameSubnet, public)
	}
}

func TestSessionPacerDeterministicAndBounded(t *testing.T) {
	start := NormalizeP2PPunchStart(P2PPunchStart{
		SessionID: "session-1",
		Token:     "token-1",
		Wire:      P2PWireSpec{RouteID: "route-1"},
	})
	left := newSessionPacer(start)
	right := newSessionPacer(start)
	if got, want := left.sprayPacketGap(1, 2, 2*time.Millisecond), right.sprayPacketGap(1, 2, 2*time.Millisecond); got != want {
		t.Fatalf("sprayPacketGap mismatch: got %s want %s", got, want)
	}
	if gap := left.sprayPacketGap(0, 0, 2*time.Millisecond); gap < minPunchBindingGap {
		t.Fatalf("sprayPacketGap = %s, want >= %s", gap, minPunchBindingGap)
	}
	if got, want := left.periodicRetryDelay(2), right.periodicRetryDelay(2); got != want {
		t.Fatalf("periodicRetryDelay mismatch: got %s want %s", got, want)
	}
}

func TestSessionPacerSeparatesRoles(t *testing.T) {
	visitor := newSessionPacer(NormalizeP2PPunchStart(P2PPunchStart{
		SessionID: "session-1",
		Token:     "token-1",
		Wire:      P2PWireSpec{RouteID: "route-1"},
		Role:      common.WORK_P2P_VISITOR,
	}))
	provider := newSessionPacer(NormalizeP2PPunchStart(P2PPunchStart{
		SessionID: "session-1",
		Token:     "token-1",
		Wire:      P2PWireSpec{RouteID: "route-1"},
		Role:      common.WORK_P2P_PROVIDER,
	}))
	if visitor.seed == provider.seed {
		t.Fatal("pacer seed should differ across roles")
	}
}

func TestBuildBirthdayPunchTargets(t *testing.T) {
	peer := P2PPeerInfo{
		Nat: NatObservation{
			PublicIP:         "1.1.1.1",
			ObservedBasePort: 5000,
			ObservedInterval: 2,
			Samples: []ProbeSample{
				{ObservedAddr: "1.1.1.1:5000"},
			},
		},
	}
	targets := BuildBirthdayPunchTargets(peer, PunchPlan{
		PredictionInterval:     2,
		BirthdayTargetsPerPort: 4,
	})
	if len(targets) < 4 {
		t.Fatalf("expected birthday targets, got %#v", targets)
	}
	if targets[0] != "1.1.1.1:5000" {
		t.Fatalf("first birthday target = %q", targets[0])
	}
}

func TestUDPPacketTokenValidation(t *testing.T) {
	packet := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeProbe)
	raw, err := EncodeUDPPacket(packet)
	if err != nil {
		t.Fatalf("EncodeUDPPacket() error = %v", err)
	}
	decoded, err := DecodeUDPPacket(raw, "token-1")
	if err != nil {
		t.Fatalf("DecodeUDPPacket() error = %v", err)
	}
	if decoded.SessionID != "session-1" || decoded.Token != "token-1" {
		t.Fatalf("decoded packet mismatch: %#v", decoded)
	}
	tamperedRaw := append([]byte(nil), raw...)
	tamperedRaw[2] ^= 0x01
	if _, err := DecodeUDPPacket(tamperedRaw, "token-1"); !errors.Is(err, ErrP2PTokenMismatch) {
		t.Fatalf("expected ErrP2PTokenMismatch, got %v", err)
	}
	if _, err := DecodeUDPPacket(raw, "wrong-token"); !errors.Is(err, ErrP2PTokenMismatch) {
		t.Fatalf("expected ErrP2PTokenMismatch for wrong token, got %v", err)
	}
	for _, plain := range [][]byte{
		[]byte("session-1"),
		[]byte("token-1"),
		[]byte(packetTypeProbe),
	} {
		if bytes.Contains(raw, plain) {
			t.Fatalf("wire packet should not expose plaintext %q", string(plain))
		}
	}
}

func TestUDPPacketEncodingAddsRandomLengthVariation(t *testing.T) {
	lengths := make(map[int]struct{}, 4)
	bodies := make(map[string]struct{}, 4)
	for i := 0; i < 8; i++ {
		packet := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeProbe)
		raw, err := EncodeUDPPacket(packet)
		if err != nil {
			t.Fatalf("EncodeUDPPacket() error = %v", err)
		}
		lengths[len(raw)] = struct{}{}
		bodies[string(raw)] = struct{}{}
		decoded, err := DecodeUDPPacket(raw, "token-1")
		if err != nil {
			t.Fatalf("DecodeUDPPacket() error = %v", err)
		}
		if decoded.SessionID != "session-1" || decoded.Type != packetTypeProbe {
			t.Fatalf("decoded packet mismatch: %#v", decoded)
		}
	}
	if len(bodies) < 2 {
		t.Fatal("encoded packets should differ because nonce/padding are randomized")
	}
	if len(lengths) < 2 {
		t.Fatalf("encoded packets should vary in length, got %v", lengths)
	}
}

func TestRunSTUNProbeEndpoint(t *testing.T) {
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, addr, err := serverConn.ReadFrom(buf)
		if err != nil {
			return
		}
		raw, err := buildFakeSTUNBindingResponse(buf[:n], addr.(*net.UDPAddr))
		if err != nil {
			t.Errorf("buildFakeSTUNBindingResponse() error = %v", err)
			return
		}
		_, _ = serverConn.WriteTo(raw, addr)
	}()

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()

	sample, err := runSTUNProbeEndpoint(context.Background(), localConn, P2PProbeEndpoint{
		ID:       "stun-1",
		Provider: ProbeProviderSTUN,
		Mode:     ProbeModeBinding,
		Network:  ProbeNetworkUDP,
		Address:  serverConn.LocalAddr().String(),
	}, 300*time.Millisecond)
	<-done
	if err != nil {
		t.Fatalf("runSTUNProbeEndpoint() error = %v", err)
	}
	if sample.Provider != ProbeProviderSTUN || sample.Mode != ProbeModeBinding {
		t.Fatalf("unexpected STUN sample %#v", sample)
	}
	if common.GetPortByAddr(sample.ObservedAddr) != common.GetPortByAddr(localConn.LocalAddr().String()) {
		t.Fatalf("ObservedAddr port = %d, want %d", common.GetPortByAddr(sample.ObservedAddr), common.GetPortByAddr(localConn.LocalAddr().String()))
	}
	if sample.ServerReplyAddr != serverConn.LocalAddr().String() {
		t.Fatalf("ServerReplyAddr = %q, want %q", sample.ServerReplyAddr, serverConn.LocalAddr().String())
	}
}

func TestRunSTUNCalibrationFallsBackToNextEndpoint(t *testing.T) {
	silentConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(silent) error = %v", err)
	}
	defer func() { _ = silentConn.Close() }()
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, addr, err := serverConn.ReadFrom(buf)
		if err != nil {
			return
		}
		raw, err := buildFakeSTUNBindingResponse(buf[:n], addr.(*net.UDPAddr))
		if err != nil {
			t.Errorf("buildFakeSTUNBindingResponse() error = %v", err)
			return
		}
		_, _ = serverConn.WriteTo(raw, addr)
	}()
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()
	sample, err := runSTUNCalibration(context.Background(), localConn, []P2PProbeEndpoint{
		{ID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Network: ProbeNetworkUDP, Address: silentConn.LocalAddr().String(), Options: map[string]string{"timeout_ms": "120"}},
		{ID: "stun-2", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Network: ProbeNetworkUDP, Address: serverConn.LocalAddr().String(), Options: map[string]string{"timeout_ms": "120"}},
	}, 1000)
	<-done
	if err != nil {
		t.Fatalf("runSTUNCalibration() error = %v", err)
	}
	if sample.EndpointID != "stun-2" {
		t.Fatalf("EndpointID = %q, want stun-2", sample.EndpointID)
	}
}

func TestRunSTUNProbesDiscoversOtherAddress(t *testing.T) {
	server1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server1) error = %v", err)
	}
	defer func() { _ = server1.Close() }()
	server2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server2) error = %v", err)
	}
	defer func() { _ = server2.Close() }()

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		buf := make([]byte, 1500)
		n, addr, err := server1.ReadFrom(buf)
		if err != nil {
			return
		}
		raw, err := buildFakeSTUNBindingResponseWithAttrs(buf[:n], addr.(*net.UDPAddr), &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 3478}, server2.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Errorf("buildFakeSTUNBindingResponseWithAttrs(server1) error = %v", err)
			return
		}
		_, _ = server1.WriteTo(raw, addr)
	}()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		buf := make([]byte, 1500)
		n, addr, err := server2.ReadFrom(buf)
		if err != nil {
			return
		}
		raw, err := buildFakeSTUNBindingResponseWithAttrs(buf[:n], addr.(*net.UDPAddr), &net.UDPAddr{IP: net.ParseIP("198.51.100.11"), Port: 3478}, nil)
		if err != nil {
			t.Errorf("buildFakeSTUNBindingResponseWithAttrs(server2) error = %v", err)
			return
		}
		_, _ = server2.WriteTo(raw, addr)
	}()

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()

	samples, err := runSTUNProbes(context.Background(), localConn, []P2PProbeEndpoint{
		{ID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Network: ProbeNetworkUDP, Address: server1.LocalAddr().String(), Options: map[string]string{"timeout_ms": "150"}},
	}, 1000)
	<-done1
	<-done2
	if err != nil {
		t.Fatalf("runSTUNProbes() error = %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("len(samples) = %d, want 2 (%#v)", len(samples), samples)
	}
	if samples[0].ServerReplyAddr != "198.51.100.10:3478" {
		t.Fatalf("samples[0].ServerReplyAddr = %q, want %q", samples[0].ServerReplyAddr, "198.51.100.10:3478")
	}
	if samples[1].ServerReplyAddr != "198.51.100.11:3478" {
		t.Fatalf("samples[1].ServerReplyAddr = %q, want %q", samples[1].ServerReplyAddr, "198.51.100.11:3478")
	}
	obs := BuildNatObservation(samples, true)
	if obs.ProbeIPCount != 2 {
		t.Fatalf("ProbeIPCount = %d, want 2", obs.ProbeIPCount)
	}
	if obs.MappingBehavior != NATMappingEndpointIndependent {
		t.Fatalf("MappingBehavior = %q, want %q (%#v)", obs.MappingBehavior, NATMappingEndpointIndependent, obs)
	}
}

func TestRunSTUNProbeEndpointTimesOutQuickly(t *testing.T) {
	silentConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(silent) error = %v", err)
	}
	defer func() { _ = silentConn.Close() }()
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()
	started := time.Now()
	_, err = runSTUNProbeEndpoint(context.Background(), localConn, P2PProbeEndpoint{
		ID:       "stun-1",
		Provider: ProbeProviderSTUN,
		Mode:     ProbeModeBinding,
		Network:  ProbeNetworkUDP,
		Address:  silentConn.LocalAddr().String(),
	}, 120*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout from silent STUN endpoint")
	}
	if elapsed := time.Since(started); elapsed > 400*time.Millisecond {
		t.Fatalf("stun timeout took too long: %s", elapsed)
	}
}

func TestResolveUDPAddrContextPrefersLocalSocketFamily(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()

	lookup, err := net.DefaultResolver.LookupIPAddr(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupIPAddr(localhost) error = %v", err)
	}
	hasV4 := false
	for _, addr := range lookup {
		if ip := common.NormalizeIP(addr.IP); ip != nil && ip.To4() != nil {
			hasV4 = true
			break
		}
	}
	if !hasV4 {
		t.Skip("localhost does not resolve to IPv4 on this host")
	}

	resolved, err := resolveUDPAddrContext(context.Background(), localConn.LocalAddr(), "localhost:3478", 250*time.Millisecond)
	if err != nil {
		t.Fatalf("resolveUDPAddrContext() error = %v", err)
	}
	if resolved.IP == nil || resolved.IP.To4() == nil {
		t.Fatalf("resolveUDPAddrContext() = %v, want IPv4 address", resolved)
	}
}

func TestResolveUDPAddrContextRejectsMismatchedLiteralFamily(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()

	if _, err := resolveUDPAddrContext(context.Background(), localConn.LocalAddr(), "[::1]:3478", 250*time.Millisecond); err == nil {
		t.Fatal("expected mismatched literal family to be rejected")
	}
}

func TestRunProbeAllowsSTUNOnlyCompatibility(t *testing.T) {
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, addr, err := serverConn.ReadFrom(buf)
		if err != nil {
			return
		}
		raw, err := buildFakeSTUNBindingResponse(buf[:n], addr.(*net.UDPAddr))
		if err != nil {
			t.Errorf("buildFakeSTUNBindingResponse() error = %v", err)
			return
		}
		_, _ = serverConn.WriteTo(raw, addr)
	}()

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()
	obs, err := runProbe(context.Background(), localConn, P2PPunchStart{
		SessionID: "session-1",
		Token:     "token-1",
		Role:      common.WORK_P2P_VISITOR,
		Probe: P2PProbeConfig{
			Version:  2,
			Provider: ProbeProviderSTUN,
			Mode:     ProbeModeBinding,
			Network:  ProbeNetworkUDP,
			Endpoints: []P2PProbeEndpoint{
				{ID: "stun-1", Provider: ProbeProviderSTUN, Mode: ProbeModeBinding, Network: ProbeNetworkUDP, Address: serverConn.LocalAddr().String()},
			},
		},
		Timeouts: DefaultTimeouts(),
	})
	if err != nil {
		t.Fatalf("runProbe() error = %v", err)
	}
	if obs.PublicIP == "" {
		t.Fatalf("stun-only probe should still observe a public address, got %#v", obs)
	}
}

func TestCompatibleNPSProbeEndpointsFiltersBySocketFamily(t *testing.T) {
	v4Conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(v4) error = %v", err)
	}
	defer func() { _ = v4Conn.Close() }()

	endpoints := compatibleNPSProbeEndpoints(v4Conn.LocalAddr(), []P2PProbeEndpoint{
		{ID: "v4", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10206"},
		{ID: "v6", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "[::1]:10206"},
		{ID: "host", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "probe.example.test:10206"},
	})
	if len(endpoints) != 2 {
		t.Fatalf("len(endpoints) = %d, want 2 (%#v)", len(endpoints), endpoints)
	}
	if endpoints[0].ID != "v4" || endpoints[1].ID != "host" {
		t.Fatalf("unexpected compatible endpoints %#v", endpoints)
	}
	if network := probeResolveNetwork(v4Conn.LocalAddr()); network != "udp4" {
		t.Fatalf("probeResolveNetwork(v4) = %q, want udp4", network)
	}
}

func TestChooseLocalProbeAddrPrefersFamilyWithMoreNPSEndpoints(t *testing.T) {
	if _, err := common.GetLocalUdp4Addr(); err != nil {
		t.Skip("local IPv4 UDP addr unavailable")
	}
	addr, err := ChooseLocalProbeAddr(P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "v6-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "[::1]:10206"},
			{ID: "v4-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10207"},
			{ID: "v4-2", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10208"},
		},
	})
	if err != nil {
		t.Fatalf("ChooseLocalProbeAddr() error = %v", err)
	}
	if family := detectAddressFamily(addr); family != udpFamilyV4 {
		t.Fatalf("ChooseLocalProbeAddr() = %q, want IPv4 family", addr)
	}
}

func TestChooseLocalProbeAddrsIncludesDualStackWhenBothFamiliesUsable(t *testing.T) {
	if _, err := common.GetLocalUdp4Addr(); err != nil {
		t.Skip("local IPv4 UDP addr unavailable")
	}
	if _, err := common.GetLocalUdp6Addr(); err != nil {
		t.Skip("local IPv6 UDP addr unavailable")
	}
	addrs, err := ChooseLocalProbeAddrs("", P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "v4-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10207"},
			{ID: "v6-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "[::1]:10208"},
		},
	})
	if err != nil {
		t.Fatalf("ChooseLocalProbeAddrs() error = %v", err)
	}
	if len(addrs) < 2 {
		t.Fatalf("dual-stack probe selection should keep both families, got %#v", addrs)
	}
	if detectAddressFamily(addrs[0]) == detectAddressFamily(addrs[1]) {
		t.Fatalf("expected both IPv4 and IPv6 probe addrs, got %#v", addrs)
	}
}

func TestChooseLocalProbeAddrsPrefersExplicitBindIP(t *testing.T) {
	addrs, err := ChooseLocalProbeAddrs("127.0.0.1", P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "v4-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10207"},
		},
	})
	if err != nil {
		t.Fatalf("ChooseLocalProbeAddrs() error = %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "127.0.0.1:0" {
		t.Fatalf("ChooseLocalProbeAddrs() = %#v, want explicit bind addr first", addrs)
	}
	if len(addrs) != 1 {
		t.Fatalf("ChooseLocalProbeAddrs() should keep a single candidate for the same family, got %#v", addrs)
	}
}

func TestChooseLocalProbeAddrsDoesNotForceUnsupportedPreferredFamily(t *testing.T) {
	addrs, err := ChooseLocalProbeAddrs("2001:db8::10", P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "v4-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10207"},
		},
	})
	if err != nil {
		t.Fatalf("ChooseLocalProbeAddrs() error = %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("ChooseLocalProbeAddrs() should keep a usable fallback family")
	}
	if detectAddressFamily(addrs[0]) != udpFamilyV4 {
		t.Fatalf("ChooseLocalProbeAddrs() should not force unsupported preferred family, got %#v", addrs)
	}
}

func TestChooseLocalProbeAddrsUsesPreferredOnlyWithinMatchingFamily(t *testing.T) {
	if _, err := common.GetLocalUdp6Addr(); err != nil {
		t.Skip("local IPv6 UDP addr unavailable")
	}
	addrs, err := ChooseLocalProbeAddrs("127.0.0.1", P2PProbeConfig{
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "v4-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "127.0.0.1:10207"},
			{ID: "v6-1", Provider: ProbeProviderNPS, Mode: ProbeModeUDP, Network: ProbeNetworkUDP, Address: "[::1]:10208"},
		},
	})
	if err != nil {
		t.Fatalf("ChooseLocalProbeAddrs() error = %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("ChooseLocalProbeAddrs() should keep one candidate per family, got %#v", addrs)
	}
	var v4Count, v6Count int
	for _, addr := range addrs {
		switch family := detectAddressFamily(addr); family {
		case udpFamilyV4:
			v4Count++
			if addr != "127.0.0.1:0" {
				t.Fatalf("expected explicit IPv4 bind addr, got %#v", addrs)
			}
		case udpFamilyV6:
			v6Count++
		case udpFamilyAny:
			t.Fatalf("expected concrete UDP family for %q", addr)
		default:
			t.Fatalf("unexpected UDP family %q for %q", family.String(), addr)
		}
	}
	if v4Count != 1 || v6Count != 1 {
		t.Fatalf("ChooseLocalProbeAddrs() should keep exactly one candidate per family, got %#v", addrs)
	}
}

func TestPeerInfoForFamilyReturnsSplitFamilyView(t *testing.T) {
	peer := BuildPeerInfo(common.WORK_P2P_VISITOR, common.CONN_KCP, "", []P2PFamilyInfo{
		{
			Family:     "udp4",
			Nat:        NatObservation{PublicIP: "1.1.1.1", ObservedBasePort: 5000, Samples: []ProbeSample{{ObservedAddr: "1.1.1.1:5000"}}},
			LocalAddrs: []string{"192.168.0.10:4000"},
		},
		{
			Family:     "udp6",
			Nat:        NatObservation{PublicIP: "2001:db8::1", ObservedBasePort: 6000, Samples: []ProbeSample{{ObservedAddr: "[2001:db8::1]:6000"}}},
			LocalAddrs: []string{"[fd00::10]:4000"},
		},
	})
	v6, ok := PeerInfoForFamily(peer, udpFamilyV6)
	if !ok {
		t.Fatal("PeerInfoForFamily(udp6) should succeed")
	}
	if v6.Nat.PublicIP != "2001:db8::1" || len(v6.Families) != 1 || v6.Families[0].Family != "udp6" {
		t.Fatalf("unexpected udp6 peer info %#v", v6)
	}
}

func TestBuildPeerInfoUsesConservativePrimaryFamilyAndMergedLocalAddrs(t *testing.T) {
	peer := BuildPeerInfo(common.WORK_P2P_VISITOR, common.CONN_KCP, "", []P2PFamilyInfo{
		{
			Family: "udp4",
			Nat: NatObservation{
				PublicIP:            "1.1.1.1",
				ObservedBasePort:    5000,
				NATType:             NATTypeRestrictedCone,
				ClassificationLevel: ClassificationConfidenceMed,
			},
			LocalAddrs: []string{"192.168.0.10:4000"},
		},
		{
			Family: "udp6",
			Nat: NatObservation{
				PublicIP:             "2001:db8::1",
				ObservedBasePort:     6000,
				NATType:              NATTypeSymmetric,
				MappingConfidenceLow: true,
				ClassificationLevel:  ClassificationConfidenceLow,
			},
			LocalAddrs: []string{"[fd00::10]:4000"},
		},
	})
	if peer.Nat.NATType != NATTypeSymmetric {
		t.Fatalf("top-level peer nat should keep the conservative family view, got %#v", peer.Nat)
	}
	if len(peer.LocalAddrs) != 2 {
		t.Fatalf("top-level peer local addrs should merge all families, got %#v", peer.LocalAddrs)
	}
}

func TestFilterPunchTargetsForLocalAddrKeepsRuntimeFamilyOnly(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()

	filtered := filterPunchTargetsForLocalAddr(localConn.LocalAddr(), []string{
		"127.0.0.1:4000",
		"[::1]:4000",
		"127.0.0.1:4000",
		"192.168.1.10:4000",
	})
	if len(filtered) != 2 {
		t.Fatalf("len(filtered) = %d, want 2 (%#v)", len(filtered), filtered)
	}
	if filtered[0] != "127.0.0.1:4000" || filtered[1] != "192.168.1.10:4000" {
		t.Fatalf("unexpected filtered targets %#v", filtered)
	}
}

func TestBasePeriodicSprayDelayBackoffAndCap(t *testing.T) {
	if delay := basePeriodicSprayDelay(0); delay != 1500*time.Millisecond {
		t.Fatalf("attempt 0 delay = %s, want 1500ms", delay)
	}
	if delay := basePeriodicSprayDelay(1); delay != 2100*time.Millisecond {
		t.Fatalf("attempt 1 delay = %s, want 2100ms", delay)
	}
	if delay := basePeriodicSprayDelay(2); delay != 2400*time.Millisecond {
		t.Fatalf("attempt 2 delay = %s, want 2400ms", delay)
	}
	if delay := basePeriodicSprayDelay(6); delay != 4*time.Second {
		t.Fatalf("attempt 6 delay = %s, want capped 4s", delay)
	}
}

func TestSleepContextReturnsEarlyOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	if sleepContext(ctx, 5*time.Second) {
		t.Fatal("sleepContext should stop when context is canceled")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("sleepContext returned too slowly after %s", elapsed)
	}
}

func TestRunPeriodicSprayReturnsImmediatelyWhenNominated(t *testing.T) {
	manager := NewCandidateManager("")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	if _, ok := manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002"); !ok {
		t.Fatal("expected nomination to succeed")
	}
	session := &runtimeSession{
		cm: manager,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	started := time.Now()
	session.runPeriodicSpray(ctx, nil, nil)
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("runPeriodicSpray() returned too slowly after nomination: %s", elapsed)
	}
}

func TestResolvePunchTargetsCachesResolvedAddrsAndPreservesIndices(t *testing.T) {
	session := &runtimeSession{}
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000}
	targets := []string{"127.0.0.1:5000", "bad target", "127.0.0.1:5001"}

	first := session.resolvePunchTargets(localAddr, targets)
	if len(first) != 2 {
		t.Fatalf("len(first) = %d, want 2", len(first))
	}
	if first[0].index != 0 || first[1].index != 2 {
		t.Fatalf("resolved indices = %#v, want [0 2]", []int{first[0].index, first[1].index})
	}
	if len(session.resolvedTargetAddrs) != 2 {
		t.Fatalf("cache size = %d, want 2", len(session.resolvedTargetAddrs))
	}

	second := session.resolvePunchTargets(localAddr, targets)
	if len(second) != len(first) {
		t.Fatalf("len(second) = %d, want %d", len(second), len(first))
	}
	if second[0].addr != first[0].addr || second[1].addr != first[1].addr {
		t.Fatal("resolved target cache should reuse parsed UDP addresses within the session")
	}
}

func TestRuntimeSessionStartSprayEnablesBirthdayFallbackAfterTargetSpray(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()
	targetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(target) error = %v", err)
	}
	defer func() { _ = targetConn.Close() }()

	session := &runtimeSession{
		start:     P2PPunchStart{SessionID: "session-1", Token: "token-1", Role: common.WORK_P2P_VISITOR},
		summary:   P2PProbeSummary{Self: P2PPeerInfo{LocalAddrs: []string{localConn.LocalAddr().String()}}, Peer: P2PPeerInfo{Nat: NatObservation{PublicIP: "127.0.0.1", ObservedBasePort: common.GetPortByAddr(targetConn.LocalAddr().String()), Samples: []ProbeSample{{ObservedAddr: targetConn.LocalAddr().String()}}}}},
		plan:      PunchPlan{UseTargetSpray: true, AllowBirthdayFallback: true, SprayRounds: 1, SprayBurst: 1, SprayPerPacketSleep: 0, SprayBurstGap: 0, SprayPhaseGap: 0, BirthdayListenPorts: 2, BirthdayTargetsPerPort: 1, PredictionIntervals: []int{1}},
		localConn: localConn,
		sockets:   []net.PacketConn{localConn},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	defer session.closeSockets(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	session.startSpray(ctx)

	if !session.plan.UseBirthdayAttack {
		t.Fatal("birthday fallback should be enabled after target spray fails")
	}
	if len(session.snapshotSockets()) < 2 {
		t.Fatalf("birthday fallback should open additional sockets, got %d", len(session.snapshotSockets()))
	}
}

func TestDirectPhaseBurstCapsAtFourPackets(t *testing.T) {
	if got := directPhaseBurst(PunchPlan{SprayBurst: 8}); got != 4 {
		t.Fatalf("directPhaseBurst(8) = %d, want 4", got)
	}
	if got := directPhaseBurst(PunchPlan{SprayBurst: 3}); got != 3 {
		t.Fatalf("directPhaseBurst(3) = %d, want 3", got)
	}
}

func TestRuntimeSessionStartSprayDoesNotEnableBirthdayFallbackWhenDisabled(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()
	targetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(target) error = %v", err)
	}
	defer func() { _ = targetConn.Close() }()

	session := &runtimeSession{
		start:     P2PPunchStart{SessionID: "session-1", Token: "token-1", Role: common.WORK_P2P_VISITOR},
		summary:   P2PProbeSummary{Self: P2PPeerInfo{LocalAddrs: []string{localConn.LocalAddr().String()}}, Peer: P2PPeerInfo{Nat: NatObservation{PublicIP: "127.0.0.1", ObservedBasePort: common.GetPortByAddr(targetConn.LocalAddr().String()), Samples: []ProbeSample{{ObservedAddr: targetConn.LocalAddr().String()}}}}},
		plan:      PunchPlan{UseTargetSpray: true, AllowBirthdayFallback: false, SprayRounds: 1, SprayBurst: 1, SprayPerPacketSleep: 0, SprayBurstGap: 0, SprayPhaseGap: 0, PredictionIntervals: []int{1}},
		localConn: localConn,
		sockets:   []net.PacketConn{localConn},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	defer session.closeSockets(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	session.startSpray(ctx)

	if session.plan.UseBirthdayAttack {
		t.Fatal("birthday fallback should stay disabled when AllowBirthdayFallback=false")
	}
	if len(session.snapshotSockets()) != 1 {
		t.Fatalf("disabled birthday fallback should keep one socket, got %d", len(session.snapshotSockets()))
	}
}

func TestWorkerForConfirmedPairMatchesAdditionalSocketOwner(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer func() { _ = localConn.Close() }()
	extraConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(extra) error = %v", err)
	}
	defer func() { _ = extraConn.Close() }()

	rs := &runtimeSession{
		localConn: localConn,
		sockets:   []net.PacketConn{localConn, extraConn},
	}
	worker := &runtimeFamilyWorker{family: udpFamilyV4, rs: rs}
	pair := confirmedPair{
		owner:      rs,
		conn:       extraConn,
		localAddr:  extraConn.LocalAddr().String(),
		remoteAddr: "1.1.1.1:5000",
	}
	if got := workerForConfirmedPair([]*runtimeFamilyWorker{worker}, pair); got != worker {
		t.Fatalf("workerForConfirmedPair() = %#v, want owner worker", got)
	}
}

func TestReadBridgeJSONHandlesAbort(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		bridgeConn := conn.NewConn(server)
		_ = WriteBridgeMessage(bridgeConn, common.P2P_PUNCH_ABORT, P2PPunchAbort{
			SessionID: "session-1",
			Role:      common.WORK_P2P_VISITOR,
			Reason:    "probe failed",
		})
	}()

	_, err := ReadBridgeJSON[P2PProbeSummary](conn.NewConn(client), common.P2P_PROBE_SUMMARY)
	<-writeDone
	if !errors.Is(err, ErrP2PSessionAbort) {
		t.Fatalf("expected ErrP2PSessionAbort, got %v", err)
	}
}

func TestCandidateManagerConfirmedRemote(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Confirm("0.0.0.0:3000", "1.1.1.1:5002")
	if got := manager.ConfirmedRemote(); got != "1.1.1.1:5002" {
		t.Fatalf("ConfirmedRemote() = %q, want %q", got, "1.1.1.1:5002")
	}
}

func TestCandidateManagerSeedsCandidateRemoteFromRendezvous(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	if got := manager.CandidateRemote(); got != "1.1.1.1:5000" {
		t.Fatalf("CandidateRemote() = %q, want rendezvous remote", got)
	}
}

func TestCandidateManagerKeepsConfirmedRemoteStable(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Confirm("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5010")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5010")
	manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5010")
	if got := manager.ConfirmedRemote(); got != "1.1.1.1:5002" {
		t.Fatalf("ConfirmedRemote() changed to %q", got)
	}
	if got := manager.CandidateRemote(); got != "1.1.1.1:5002" {
		t.Fatalf("CandidateRemote() should stay on confirmed remote, got %q", got)
	}
}

func TestCandidateManagerSingleNomination(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Observe("0.0.0.0:3001", "1.1.1.1:5010")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3001", "1.1.1.1:5010")
	if _, ok := manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002"); !ok {
		t.Fatal("first nomination should succeed")
	}
	if _, ok := manager.TryNominate("0.0.0.0:3001", "1.1.1.1:5010"); ok {
		t.Fatal("second nomination should be blocked")
	}
	pair := manager.NominatedPair()
	if pair == nil || pair.LocalAddr != "0.0.0.0:3000" || pair.RemoteAddr != "1.1.1.1:5002" {
		t.Fatalf("unexpected nominated pair %#v", pair)
	}
}

func TestCandidateManagerTryNominateBestPrefersHigherScore(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Observe("0.0.0.0:3001", "1.1.1.1:5010")
	manager.MarkSucceededWithPriority("0.0.0.0:3001", "1.1.1.1:5010", CandidatePriority{
		Score:  100,
		Reason: "target[1]",
	})
	manager.MarkSucceededWithPriority("0.0.0.0:3000", "1.1.1.1:5002", CandidatePriority{
		Score:  200,
		Reason: "direct[0]",
	})
	pair, ok := manager.TryNominateBest()
	if !ok {
		t.Fatal("best nomination should succeed")
	}
	if pair == nil || pair.LocalAddr != "0.0.0.0:3000" || pair.RemoteAddr != "1.1.1.1:5002" {
		t.Fatalf("unexpected nominated pair %#v", pair)
	}
	if pair.Score != 200 || pair.ScoreReason != "direct[0]" {
		t.Fatalf("unexpected candidate priority %#v", pair)
	}
}

func TestCandidateManagerReleaseNominationRestoresSucceededState(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceededWithPriority("0.0.0.0:3000", "1.1.1.1:5002", CandidatePriority{
		Score:  200,
		Reason: "direct[0]",
	})
	if _, ok := manager.TryNominateBest(); !ok {
		t.Fatal("best nomination should succeed")
	}
	pair := manager.ReleaseNomination("0.0.0.0:3000", "1.1.1.1:5002")
	if pair == nil {
		t.Fatal("ReleaseNomination should return nominated pair")
	}
	if pair.State != CandidateSucceeded || pair.Nominated {
		t.Fatalf("released pair should return to succeeded state, got %#v", pair)
	}
	if manager.NominatedPair() != nil {
		t.Fatal("nominated pair should be cleared after release")
	}
}

func TestCandidateManagerAdoptNominationReplacesOlderPair(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3001", "1.1.1.1:5010")
	if _, ok := manager.AdoptNomination("0.0.0.0:3000", "1.1.1.1:5002"); !ok {
		t.Fatal("first adopt nomination should succeed")
	}
	if _, ok := manager.AdoptNomination("0.0.0.0:3001", "1.1.1.1:5010"); !ok {
		t.Fatal("second adopt nomination should replace the first pair")
	}
	pair := manager.NominatedPair()
	if pair == nil || pair.LocalAddr != "0.0.0.0:3001" || pair.RemoteAddr != "1.1.1.1:5010" {
		t.Fatalf("unexpected nominated pair %#v", pair)
	}
	if prior := manager.candidates[candidateKey("0.0.0.0:3000", "1.1.1.1:5002")]; prior == nil || prior.Nominated || prior.State != CandidateSucceeded {
		t.Fatalf("old nominated pair should revert to succeeded, got %#v", prior)
	}
}

func TestCandidateManagerBackoffNominationSkipsCoolingPair(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.MarkSucceededWithPriority("0.0.0.0:3000", "1.1.1.1:5002", CandidatePriority{
		Score:  200,
		Reason: "direct[0]",
	})
	manager.MarkSucceededWithPriority("0.0.0.0:3001", "1.1.1.1:5010", CandidatePriority{
		Score:  150,
		Reason: "target[0]",
	})
	if _, ok := manager.TryNominateBest(); !ok {
		t.Fatal("best nomination should succeed")
	}
	if pair := manager.BackoffNomination("0.0.0.0:3000", "1.1.1.1:5002", 500*time.Millisecond); pair == nil {
		t.Fatal("BackoffNomination should return the previously nominated pair")
	}
	pair, ok := manager.TryNominateBest()
	if !ok {
		t.Fatal("cooling pair should allow the next candidate to be nominated")
	}
	if pair.LocalAddr != "0.0.0.0:3001" || pair.RemoteAddr != "1.1.1.1:5010" {
		t.Fatalf("unexpected nominated pair %#v", pair)
	}
}

func TestCandidateManagerRequiresNominationBeforeConfirm(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	if pair := manager.Confirm("0.0.0.0:3000", "1.1.1.1:5002"); pair != nil {
		t.Fatalf("confirm should fail without nomination, got %#v", pair)
	}
	if manager.ConfirmedPair() != nil {
		t.Fatal("confirmed pair should stay empty without nomination")
	}
}

func TestCandidateManagerRejectsCrossPairConfirm(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Observe("0.0.0.0:3001", "1.1.1.1:5010")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3001", "1.1.1.1:5010")
	if _, ok := manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002"); !ok {
		t.Fatal("nomination should succeed for first pair")
	}
	if pair := manager.Confirm("0.0.0.0:3001", "1.1.1.1:5010"); pair != nil {
		t.Fatalf("cross-pair confirm should be rejected, got %#v", pair)
	}
	if pair := manager.ConfirmedPair(); pair != nil {
		t.Fatalf("unexpected confirmed pair %#v", pair)
	}
	if pair := manager.Confirm("0.0.0.0:3000", "1.1.1.1:5002"); pair == nil {
		t.Fatal("nominated pair should confirm successfully")
	}
}

func TestCandidateManagerClosesOtherPairsAfterConfirm(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	manager.Observe("0.0.0.0:3001", "1.1.1.1:5010")
	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	manager.MarkSucceeded("0.0.0.0:3001", "1.1.1.1:5010")
	manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002")
	if pair := manager.Confirm("0.0.0.0:3000", "1.1.1.1:5002"); pair == nil {
		t.Fatal("expected nominated pair to confirm")
	}
	if state := manager.candidates[candidateKey("0.0.0.0:3001", "1.1.1.1:5010")].State; state != CandidateClosed {
		t.Fatalf("other candidate state = %s, want %s", state, CandidateClosed)
	}
	manager.MarkSucceeded("0.0.0.0:3001", "1.1.1.1:5010")
	if state := manager.candidates[candidateKey("0.0.0.0:3001", "1.1.1.1:5010")].State; state != CandidateClosed {
		t.Fatalf("closed candidate should stay closed, got %s", state)
	}
}

func TestSplitBrainNominationConvergesToSinglePair(t *testing.T) {
	visitor := NewCandidateManager("1.1.1.1:5000")
	provider := NewCandidateManager("2.2.2.2:6000")

	visitor.Observe("v-local-1", "p-remote-1")
	visitor.Observe("v-local-2", "p-remote-2")
	visitor.MarkSucceeded("v-local-1", "p-remote-1")
	visitor.MarkSucceeded("v-local-2", "p-remote-2")

	provider.Observe("p-local-1", "v-remote-1")
	provider.Observe("p-local-2", "v-remote-2")
	provider.MarkSucceeded("p-local-1", "v-remote-1")
	provider.MarkSucceeded("p-local-2", "v-remote-2")

	if _, ok := visitor.TryNominate("v-local-2", "p-remote-2"); !ok {
		t.Fatal("visitor should nominate one winning pair")
	}
	if _, ok := provider.TryNominate("p-local-2", "v-remote-2"); !ok {
		t.Fatal("provider should accept the same nominated pair once END arrives")
	}
	if provider.Confirm("p-local-2", "v-remote-2") == nil {
		t.Fatal("provider should confirm nominated pair")
	}
	if visitor.Confirm("v-local-2", "p-remote-2") == nil {
		t.Fatal("visitor should confirm nominated pair after ACCEPT")
	}
	if pair := visitor.ConfirmedPair(); pair == nil || pair.LocalAddr != "v-local-2" || pair.RemoteAddr != "p-remote-2" {
		t.Fatalf("unexpected visitor confirmed pair %#v", pair)
	}
	if pair := visitor.candidates[candidateKey("v-local-1", "p-remote-1")]; pair == nil || pair.State != CandidateClosed {
		t.Fatalf("losing visitor pair should close, got %#v", pair)
	}
	if pair := provider.candidates[candidateKey("p-local-1", "v-remote-1")]; pair == nil || pair.State != CandidateClosed {
		t.Fatalf("losing provider pair should close, got %#v", pair)
	}
}

func TestRuntimeSessionKeepsConfirmedRemoteStable(t *testing.T) {
	session := &runtimeSession{}
	session.updateCandidateRemote("1.1.1.1:5002")
	session.updateConfirmedRemote("1.1.1.1:5002")
	session.updateCandidateRemote("1.1.1.1:5010")
	if session.endpoints.CandidateRemote != "1.1.1.1:5002" {
		t.Fatalf("CandidateRemote changed to %q", session.endpoints.CandidateRemote)
	}
	if session.endpoints.ConfirmedRemote != "1.1.1.1:5002" {
		t.Fatalf("ConfirmedRemote changed to %q", session.endpoints.ConfirmedRemote)
	}
}

func TestRuntimeSessionDropsWrongTokenSilently(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_VISITOR,
		},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	wrong := newUDPPacket("session-1", "wrong-token", common.WORK_P2P_PROVIDER, packetTypeSucc)
	wrongRaw, err := EncodeUDPPacket(wrong)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(wrong) error = %v", err)
	}
	if _, err := sendConn.WriteTo(wrongRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(wrong) error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if session.cm.NominatedPair() != nil || session.cm.ConfirmedPair() != nil || session.endpoints.CandidateRemote != "" {
		t.Fatal("wrong-token packet should be silently dropped")
	}
	if stats := session.snapshotStats(); stats.tokenMismatchDropped == 0 {
		t.Fatal("wrong-token packet should increase mismatch counter")
	}

	right := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeSucc)
	rightRaw, err := EncodeUDPPacket(right)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(right) error = %v", err)
	}
	if _, err := sendConn.WriteTo(rightRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(right) error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	pair := session.cm.NominatedPair()
	if pair == nil {
		t.Fatal("valid packet should still progress handshake after wrong-token packet")
	}
	if pair.RemoteAddr != sendConn.LocalAddr().String() {
		t.Fatalf("nominated remote = %q, want %q", pair.RemoteAddr, sendConn.LocalAddr().String())
	}
	if stats := session.snapshotStats(); !stats.tokenVerified {
		t.Fatal("valid packet should mark token verified")
	}
}

func TestRuntimeSessionDropsWrongWireRouteSilently(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Wire:      P2PWireSpec{RouteID: "route-a"},
			Role:      common.WORK_P2P_VISITOR,
		},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	wrongRoute := newUDPPacketWithWire("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeSucc, P2PWireSpec{RouteID: "route-b"})
	wrongRouteRaw, err := EncodeUDPPacket(wrongRoute)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(wrongRoute) error = %v", err)
	}
	if _, err := sendConn.WriteTo(wrongRouteRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(wrongRoute) error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	if session.cm.NominatedPair() != nil || session.cm.ConfirmedPair() != nil || session.endpoints.CandidateRemote != "" {
		t.Fatal("wrong-route packet should be silently dropped")
	}
	if stats := session.snapshotStats(); stats.tokenMismatchDropped == 0 {
		t.Fatal("wrong-route packet should increase mismatch counter")
	}
}

func TestRuntimeSessionDropsReplaySilently(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_PROVIDER,
		},
		cm:        NewCandidateManager(""),
		replay:    NewReplayWindow(30 * time.Second),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	packet := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeProbe)
	raw, err := EncodeUDPPacket(packet)
	if err != nil {
		t.Fatalf("EncodeUDPPacket() error = %v", err)
	}
	if _, err := sendConn.WriteTo(raw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(first) error = %v", err)
	}
	if _, err := sendConn.WriteTo(raw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(replay) error = %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if stats := session.snapshotStats(); stats.replayDropped == 0 {
		t.Fatal("replayed packet should increase replay counter")
	}
}

func TestCandidateManagerPruneAndCleanup(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	key := candidateKey("0.0.0.0:3000", "1.1.1.1:5002")
	manager.candidates[key].LastSeenAt = time.Now().Add(-10 * time.Second)
	if pruned := manager.PruneStale(2 * time.Second); pruned != 1 {
		t.Fatalf("PruneStale() = %d, want 1", pruned)
	}
	if pair := manager.candidates[key]; pair == nil || pair.State != CandidateClosed {
		t.Fatalf("pair state = %#v, want %s", pair, CandidateClosed)
	}
	manager.candidates[key].LastSeenAt = time.Now().Add(-10 * time.Second)
	if removed := manager.CleanupClosed(2 * time.Second); removed != 1 {
		t.Fatalf("CleanupClosed() = %d, want 1", removed)
	}
	if len(manager.candidates) != 0 {
		t.Fatalf("cleanup should remove closed candidate, still have %#v", manager.candidates)
	}
}

func TestCandidateManagerCanReopenPrunedCandidateBeforeConfirm(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	key := candidateKey("0.0.0.0:3000", "1.1.1.1:5002")
	manager.candidates[key].LastSeenAt = time.Now().Add(-10 * time.Second)
	manager.PruneStale(2 * time.Second)
	reopened := manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	if reopened.State != CandidateDiscovered {
		t.Fatalf("reopened candidate state = %s, want %s", reopened.State, CandidateDiscovered)
	}
	succeeded := manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	if succeeded == nil || succeeded.State != CandidateSucceeded {
		t.Fatalf("reopened candidate should succeed again, got %#v", succeeded)
	}
}

func TestCandidateManagerReturnsSnapshotPairs(t *testing.T) {
	manager := NewCandidateManager("1.1.1.1:5000")
	pair := manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	if pair == nil {
		t.Fatal("Observe should return a candidate snapshot")
	}
	pair.Score = 999
	pair.State = CandidateClosed

	current := manager.Observe("0.0.0.0:3000", "1.1.1.1:5002")
	if current == nil {
		t.Fatal("Observe should still return a snapshot")
	}
	if current.Score == 999 || current.State == CandidateClosed {
		t.Fatalf("returned candidate pair should be a snapshot, got %#v", current)
	}

	manager.MarkSucceeded("0.0.0.0:3000", "1.1.1.1:5002")
	if _, nominated := manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002"); !nominated {
		t.Fatal("TryNominate should nominate the first succeeded pair")
	}
	existing, nominated := manager.TryNominate("0.0.0.0:3000", "1.1.1.1:5002")
	if nominated || existing == nil {
		t.Fatal("TryNominate should return the existing nominated snapshot")
	}
	existing.State = CandidateClosed

	if current := manager.NominatedPair(); current == nil || current.State == CandidateClosed {
		t.Fatalf("nominated pair should remain internal state, got %#v", current)
	}
}

func TestRuntimeSessionDoesNotHandoverBeforeConfirm(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_VISITOR,
		},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	success := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeSucc)
	raw, err := EncodeUDPPacket(success)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(success) error = %v", err)
	}
	if _, err := sendConn.WriteTo(raw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(success) error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	select {
	case pair := <-session.confirmed:
		t.Fatalf("session should not handover before confirm, got %#v", pair)
	default:
	}
	if session.cm.ConfirmedPair() != nil {
		t.Fatal("confirmed pair should stay empty before ACCEPT")
	}
}

func TestRuntimeSessionProviderWaitsForReadyBeforeHandover(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_PROVIDER,
		},
		plan:      PunchPlan{NominationRetryInterval: 40 * time.Millisecond},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
		accept:    make(map[string]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	end := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeEnd)
	end.NominationEpoch = 1
	endRaw, err := EncodeUDPPacket(end)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(end) error = %v", err)
	}
	if _, err := sendConn.WriteTo(endRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(end) error = %v", err)
	}
	time.Sleep(120 * time.Millisecond)

	select {
	case pair := <-session.confirmed:
		t.Fatalf("provider should not handover before READY, got %#v", pair)
	default:
	}
	if session.cm.ConfirmedPair() != nil {
		t.Fatal("provider should not mark pair confirmed before READY")
	}
	if session.cm.NominatedPair() == nil {
		t.Fatal("provider should keep a nominated pair after END")
	}

	ready := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeReady)
	ready.NominationEpoch = 1
	readyRaw, err := EncodeUDPPacket(ready)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(ready) error = %v", err)
	}
	if _, err := sendConn.WriteTo(readyRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(ready) error = %v", err)
	}

	select {
	case pair := <-session.confirmed:
		if pair.remoteAddr != sendConn.LocalAddr().String() {
			t.Fatalf("confirmed remote = %q, want %q", pair.remoteAddr, sendConn.LocalAddr().String())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("provider should handover after READY")
	}
}

func TestRuntimeSessionVisitorSendsReadyAfterAccept(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_VISITOR,
		},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	session.cm.Observe(readConn.LocalAddr().String(), sendConn.LocalAddr().String())
	session.cm.MarkSucceeded(readConn.LocalAddr().String(), sendConn.LocalAddr().String())
	if _, ok := session.cm.TryNominate(readConn.LocalAddr().String(), sendConn.LocalAddr().String()); !ok {
		t.Fatal("visitor should nominate pair before ACCEPT")
	}
	session.setOutboundNomination(readConn.LocalAddr().String(), sendConn.LocalAddr().String(), 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	accept := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeAccept)
	accept.NominationEpoch = 1
	acceptRaw, err := EncodeUDPPacket(accept)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(accept) error = %v", err)
	}
	if _, err := sendConn.WriteTo(acceptRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(accept) error = %v", err)
	}

	buf := make([]byte, 2048)
	_ = sendConn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	defer func() { _ = sendConn.SetReadDeadline(time.Time{}) }()
	receivedReady := false
	for !receivedReady {
		n, _, err := sendConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		packet, err := DecodeUDPPacket(buf[:n], "token-1")
		if err != nil {
			t.Fatalf("DecodeUDPPacket(ready) error = %v", err)
		}
		if packet.Type == packetTypeReady {
			receivedReady = true
		}
	}

	select {
	case pair := <-session.confirmed:
		if pair.remoteAddr != sendConn.LocalAddr().String() {
			t.Fatalf("confirmed remote = %q, want %q", pair.remoteAddr, sendConn.LocalAddr().String())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("visitor should handover after ACCEPT")
	}
}

func TestRuntimeSessionProviderSwitchesToHigherEpochProposal(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	firstConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(first) error = %v", err)
	}
	defer func() { _ = firstConn.Close() }()
	secondConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(second) error = %v", err)
	}
	defer func() { _ = secondConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_PROVIDER,
		},
		plan:      PunchPlan{NominationRetryInterval: 40 * time.Millisecond},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
		accept:    make(map[string]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	end1 := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeEnd)
	end1.NominationEpoch = 1
	raw1, err := EncodeUDPPacket(end1)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(end1) error = %v", err)
	}
	if _, err := firstConn.WriteTo(raw1, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(end1) error = %v", err)
	}
	time.Sleep(80 * time.Millisecond)

	end2 := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeEnd)
	end2.NominationEpoch = 2
	raw2, err := EncodeUDPPacket(end2)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(end2) error = %v", err)
	}
	if _, err := secondConn.WriteTo(raw2, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(end2) error = %v", err)
	}
	time.Sleep(120 * time.Millisecond)

	if pair := session.cm.NominatedPair(); pair == nil || pair.RemoteAddr != secondConn.LocalAddr().String() {
		t.Fatalf("provider should follow higher epoch proposal, got %#v", pair)
	}

	ready1 := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeReady)
	ready1.NominationEpoch = 1
	ready1Raw, err := EncodeUDPPacket(ready1)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(ready1) error = %v", err)
	}
	if _, err := firstConn.WriteTo(ready1Raw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(ready1) error = %v", err)
	}
	time.Sleep(120 * time.Millisecond)
	select {
	case pair := <-session.confirmed:
		t.Fatalf("stale READY should not confirm, got %#v", pair)
	default:
	}

	ready2 := newUDPPacket("session-1", "token-1", common.WORK_P2P_VISITOR, packetTypeReady)
	ready2.NominationEpoch = 2
	ready2Raw, err := EncodeUDPPacket(ready2)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(ready2) error = %v", err)
	}
	if _, err := secondConn.WriteTo(ready2Raw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(ready2) error = %v", err)
	}

	select {
	case pair := <-session.confirmed:
		if pair.remoteAddr != secondConn.LocalAddr().String() {
			t.Fatalf("confirmed remote = %q, want %q", pair.remoteAddr, secondConn.LocalAddr().String())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("provider should confirm after READY for the higher epoch proposal")
	}
}

func TestRuntimeSessionVisitorIgnoresStaleAcceptAfterRenomination(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	firstConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(first) error = %v", err)
	}
	defer func() { _ = firstConn.Close() }()
	secondConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(second) error = %v", err)
	}
	defer func() { _ = secondConn.Close() }()

	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_VISITOR,
		},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	session.cm.MarkSucceeded(readConn.LocalAddr().String(), firstConn.LocalAddr().String())
	session.cm.MarkSucceeded(readConn.LocalAddr().String(), secondConn.LocalAddr().String())
	if _, ok := session.cm.AdoptNomination(readConn.LocalAddr().String(), firstConn.LocalAddr().String()); !ok {
		t.Fatal("expected first nomination to be adopted")
	}
	session.setOutboundNomination(readConn.LocalAddr().String(), firstConn.LocalAddr().String(), 1)
	if session.cm.BackoffNomination(readConn.LocalAddr().String(), firstConn.LocalAddr().String(), time.Second) == nil {
		t.Fatal("expected first nomination to back off")
	}
	if _, ok := session.cm.AdoptNomination(readConn.LocalAddr().String(), secondConn.LocalAddr().String()); !ok {
		t.Fatal("expected second nomination to be adopted")
	}
	session.setOutboundNomination(readConn.LocalAddr().String(), secondConn.LocalAddr().String(), 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	staleAccept := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeAccept)
	staleAccept.NominationEpoch = 1
	staleRaw, err := EncodeUDPPacket(staleAccept)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(staleAccept) error = %v", err)
	}
	if _, err := firstConn.WriteTo(staleRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(staleAccept) error = %v", err)
	}
	time.Sleep(120 * time.Millisecond)
	select {
	case pair := <-session.confirmed:
		t.Fatalf("stale ACCEPT should not confirm, got %#v", pair)
	default:
	}

	accept := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeAccept)
	accept.NominationEpoch = 2
	acceptRaw, err := EncodeUDPPacket(accept)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(accept) error = %v", err)
	}
	if _, err := secondConn.WriteTo(acceptRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(accept) error = %v", err)
	}

	select {
	case pair := <-session.confirmed:
		if pair.remoteAddr != secondConn.LocalAddr().String() {
			t.Fatalf("confirmed remote = %q, want %q", pair.remoteAddr, secondConn.LocalAddr().String())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("visitor should confirm only the latest nomination epoch")
	}
}

func TestRuntimeSessionDelayedNominationPrefersHigherRankedSuccess(t *testing.T) {
	readConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(read) error = %v", err)
	}
	defer func() { _ = readConn.Close() }()
	betterConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(better) error = %v", err)
	}
	defer func() { _ = betterConn.Close() }()
	worseConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(worse) error = %v", err)
	}
	defer func() { _ = worseConn.Close() }()

	summary := P2PProbeSummary{
		Self: P2PPeerInfo{
			LocalAddrs: []string{readConn.LocalAddr().String()},
		},
		Peer: P2PPeerInfo{
			Nat: NatObservation{
				PublicIP:         "127.0.0.1",
				ObservedBasePort: common.GetPortByAddr(betterConn.LocalAddr().String()),
				Samples: []ProbeSample{
					{ObservedAddr: betterConn.LocalAddr().String()},
					{ObservedAddr: worseConn.LocalAddr().String()},
				},
			},
		},
	}
	plan := PunchPlan{
		NominationDelay:         120 * time.Millisecond,
		NominationRetryInterval: 40 * time.Millisecond,
	}
	session := &runtimeSession{
		start: P2PPunchStart{
			SessionID: "session-1",
			Token:     "token-1",
			Role:      common.WORK_P2P_VISITOR,
		},
		summary:   summary,
		plan:      plan,
		localConn: readConn,
		sockets:   []net.PacketConn{readConn},
		cm:        NewCandidateManager(""),
		ranker:    NewCandidateRanker(summary.Self, summary.Peer, plan),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.readLoopOnConn(ctx, readConn)

	worse := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeSucc)
	worseRaw, err := EncodeUDPPacket(worse)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(worse) error = %v", err)
	}
	if _, err := worseConn.WriteTo(worseRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(worse) error = %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	better := newUDPPacket("session-1", "token-1", common.WORK_P2P_PROVIDER, packetTypeSucc)
	betterRaw, err := EncodeUDPPacket(better)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(better) error = %v", err)
	}
	if _, err := betterConn.WriteTo(betterRaw, readConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(better) error = %v", err)
	}
	time.Sleep(220 * time.Millisecond)

	pair := session.cm.NominatedPair()
	if pair == nil {
		t.Fatal("expected delayed nomination to select a candidate")
	}
	if pair.RemoteAddr != betterConn.LocalAddr().String() {
		t.Fatalf("nominated remote = %q, want %q", pair.RemoteAddr, betterConn.LocalAddr().String())
	}
	if !strings.HasPrefix(pair.ScoreReason, "responsive_public(") {
		t.Fatalf("nominated pair score reason = %q, want responsive_public(...)", pair.ScoreReason)
	}
}

func TestCrosstalkPacketDoesNotAffectOtherSession(t *testing.T) {
	sessionA := &runtimeSession{
		start:     P2PPunchStart{SessionID: "session-a", Token: "token-a", Role: common.WORK_P2P_VISITOR},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}
	sessionB := &runtimeSession{
		start:     P2PPunchStart{SessionID: "session-b", Token: "token-b", Role: common.WORK_P2P_VISITOR},
		cm:        NewCandidateManager(""),
		confirmed: make(chan confirmedPair, 1),
		nominate:  make(map[string]struct{}),
	}

	readA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(readA) error = %v", err)
	}
	defer func() { _ = readA.Close() }()
	readB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(readB) error = %v", err)
	}
	defer func() { _ = readB.Close() }()
	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(send) error = %v", err)
	}
	defer func() { _ = sendConn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sessionA.readLoopOnConn(ctx, readA)
	go sessionB.readLoopOnConn(ctx, readB)

	packetA := newUDPPacket("session-a", "token-a", common.WORK_P2P_PROVIDER, packetTypeSucc)
	rawA, err := EncodeUDPPacket(packetA)
	if err != nil {
		t.Fatalf("EncodeUDPPacket(packetA) error = %v", err)
	}
	if _, err := sendConn.WriteTo(rawA, readA.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(readA) error = %v", err)
	}
	if _, err := sendConn.WriteTo(rawA, readB.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(readB) error = %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if sessionA.cm.NominatedPair() == nil {
		t.Fatal("session A should accept its own packet")
	}
	if sessionB.cm.NominatedPair() != nil || sessionB.cm.ConfirmedPair() != nil || sessionB.endpoints.CandidateRemote != "" {
		t.Fatal("session B should ignore crosstalk packet from session A")
	}
	if stats := sessionB.snapshotStats(); stats.tokenMismatchDropped == 0 {
		t.Fatal("session B should count mismatched crosstalk packet")
	}
}

func TestDefaultTimeouts(t *testing.T) {
	timeouts := DefaultTimeouts()
	if timeouts.HandshakeTimeoutMs != 20000 {
		t.Fatalf("HandshakeTimeoutMs = %d, want 20000", timeouts.HandshakeTimeoutMs)
	}
	if timeouts.TransportTimeoutMs != 10000 {
		t.Fatalf("TransportTimeoutMs = %d, want 10000", timeouts.TransportTimeoutMs)
	}
}

func TestMapP2PContextError(t *testing.T) {
	if !errors.Is(mapP2PContextError(context.DeadlineExceeded), ErrNATNotSupportP2P) {
		t.Fatal("deadline should map to ErrNATNotSupportP2P")
	}
	plainErr := errors.New("plain")
	if !errors.Is(mapP2PContextError(plainErr), plainErr) {
		t.Fatal("plain error should be returned directly")
	}
}

func TestFilteringEvidenceKnown(t *testing.T) {
	if filteringEvidenceKnown(NatObservation{}) {
		t.Fatal("empty observation should not report filtering evidence")
	}
	if !filteringEvidenceKnown(NatObservation{FilteringTested: true}) {
		t.Fatal("explicit filtering tested flag should report evidence")
	}
	if !filteringEvidenceKnown(NatObservation{FilteringBehavior: NATFilteringPortRestricted}) {
		t.Fatal("explicit filtering behavior should report evidence")
	}
	if !filteringEvidenceKnown(NatObservation{NATType: NATTypeRestrictedCone}) {
		t.Fatal("restricted cone nat type should imply filtering evidence")
	}
}

func TestIsIgnorableUDPIcmpError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "windows 10054", err: errors.New("wsarecvfrom: 10054"), want: true},
		{name: "connection refused", err: errors.New("read udp: connection refused"), want: true},
		{name: "connection reset by peer", err: errors.New("connection reset by peer"), want: true},
		{name: "other", err: errors.New("use of closed network connection"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIgnorableUDPIcmpError(tt.err); got != tt.want {
				t.Fatalf("isIgnorableUDPIcmpError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestProbeEndpointAddrs(t *testing.T) {
	addrs := probeEndpointAddrs(P2PProbeConfig{
		Version:  1,
		Provider: ProbeProviderNPS,
		Mode:     ProbeModeUDP,
		Network:  ProbeNetworkUDP,
		Endpoints: []P2PProbeEndpoint{
			{ID: "probe-1", Network: ProbeNetworkUDP, Address: "1.1.1.1:10206"},
			{ID: "probe-2", Network: ProbeNetworkUDP, Address: "bad"},
			{ID: "probe-3", Network: ProbeNetworkUDP, Address: "1.1.1.1:10208"},
		},
	})
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2 (%#v)", len(addrs), addrs)
	}
	if addrs[0] != "1.1.1.1:10206" || addrs[1] != "1.1.1.1:10208" {
		t.Fatalf("unexpected addrs %#v", addrs)
	}
}

func TestDecodeUDPPacketWithLookup(t *testing.T) {
	packet := newUDPPacket("session-lookup", "token-lookup", common.WORK_P2P_VISITOR, packetTypeProbe)
	raw, err := EncodeUDPPacket(packet)
	if err != nil {
		t.Fatalf("EncodeUDPPacket() error = %v", err)
	}
	wantRouteKey := WireRouteKey(packet.WireID)
	decoded, err := DecodeUDPPacketWithLookup(raw, func(routeKey string) (UDPPacketLookupResult, bool) {
		if routeKey != wantRouteKey {
			return UDPPacketLookupResult{}, false
		}
		return UDPPacketLookupResult{
			SessionID: "session-lookup",
			Token:     "token-lookup",
		}, true
	})
	if err != nil {
		t.Fatalf("DecodeUDPPacketWithLookup() error = %v", err)
	}
	if decoded.SessionID != "session-lookup" || decoded.Token != "token-lookup" {
		t.Fatalf("decoded packet mismatch: %#v", decoded)
	}
	if decoded.WireID != wantRouteKey {
		t.Fatalf("decoded wire route = %q, want %q", decoded.WireID, wantRouteKey)
	}
	if _, err := DecodeUDPPacketWithLookup(raw, func(routeKey string) (UDPPacketLookupResult, bool) {
		return UDPPacketLookupResult{}, false
	}); !errors.Is(err, ErrP2PTokenMismatch) {
		t.Fatalf("expected ErrP2PTokenMismatch for missing lookup, got %v", err)
	}
}

func TestReplayWindowRejectsExpiredFutureAndDuplicatePackets(t *testing.T) {
	window := NewReplayWindow(100 * time.Millisecond)
	now := time.Now().UnixMilli()
	if window.Accept(now-500, "expired") {
		t.Fatal("expired packet should be rejected")
	}
	if window.Accept(now+500, "future") {
		t.Fatal("future packet should be rejected")
	}
	if !window.Accept(now, "ok") {
		t.Fatal("fresh packet should be accepted")
	}
	if window.Accept(now, "ok") {
		t.Fatal("duplicate nonce should be rejected")
	}
}

func TestReplayWindowCapsObservedEntries(t *testing.T) {
	window := newReplayWindow(5*time.Second, 3)
	now := time.Now().UnixMilli()
	for i := 0; i < 6; i++ {
		if !window.Accept(now+int64(i), strconv.Itoa(i)) {
			t.Fatalf("nonce %d should be accepted", i)
		}
	}
	window.mu.Lock()
	size := len(window.observed)
	_, oldestPresent := window.observed["0"]
	window.mu.Unlock()
	if size != 3 {
		t.Fatalf("replay window size = %d, want capped at 3", size)
	}
	if oldestPresent {
		t.Fatal("oldest replay nonce should be evicted when the window reaches capacity")
	}
}

func TestCompatibleSTUNDerivedEndpoint(t *testing.T) {
	localV4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(v4) error = %v", err)
	}
	defer func() { _ = localV4.Close() }()

	if !compatibleSTUNDerivedEndpoint(localV4.LocalAddr(), "127.0.0.1:3479", "127.0.0.1:3478") {
		t.Fatal("same-family different endpoint should be accepted")
	}
	if compatibleSTUNDerivedEndpoint(localV4.LocalAddr(), "[::1]:3479", "") {
		t.Fatal("different-family endpoint should be rejected")
	}
	if compatibleSTUNDerivedEndpoint(localV4.LocalAddr(), "127.0.0.1:3478", "127.0.0.1:3478") {
		t.Fatal("response-origin duplicate endpoint should be rejected")
	}
}

func TestBuildHistoricalPredictionPortsOrdersByFrequency(t *testing.T) {
	resetPredictionHistoryForTest()
	t.Cleanup(resetPredictionHistoryForTest)

	obs := NatObservation{
		PublicIP:         "1.1.1.1",
		ObservedBasePort: 5000,
		ObservedInterval: 2,
		NATType:          NATTypeSymmetric,
		MappingBehavior:  NATMappingEndpointDependent,
	}
	recordPredictionSuccess(obs, "1.1.1.1:5006")
	recordPredictionSuccess(obs, "1.1.1.1:5006")
	recordPredictionSuccess(obs, "1.1.1.1:4998")
	recordPredictionSuccess(obs, "1.1.1.1:5004")

	ports := buildHistoricalPredictionPorts(obs, 4)
	if len(ports) < 3 {
		t.Fatalf("expected historical prediction ports, got %#v", ports)
	}
	if ports[0] != 5006 {
		t.Fatalf("ports[0] = %d, want 5006", ports[0])
	}
}

func TestPredictionHistoryOffsetsPreferRecentWhenFrequencyMatches(t *testing.T) {
	resetPredictionHistoryForTest()
	t.Cleanup(resetPredictionHistoryForTest)

	key := predictionHistoryKey(NatObservation{
		PublicIP:         "1.1.1.1",
		ObservedBasePort: 5000,
		ObservedInterval: 2,
		NATType:          NATTypeSymmetric,
		MappingBehavior:  NATMappingEndpointDependent,
	})
	now := time.Now()
	globalPredictionHistory.mu.Lock()
	globalPredictionHistory.entries[key] = &predictionHistoryEntry{
		updatedAt: now,
		offsets: map[int]predictionOffsetStat{
			6: {count: 2, updatedAt: now.Add(-20 * time.Minute)},
			8: {count: 2, updatedAt: now.Add(-1 * time.Minute)},
		},
	}
	globalPredictionHistory.mu.Unlock()

	offsets := predictionHistoryOffsets(NatObservation{
		PublicIP:         "1.1.1.1",
		ObservedBasePort: 5000,
		ObservedInterval: 2,
		NATType:          NATTypeSymmetric,
		MappingBehavior:  NATMappingEndpointDependent,
	})
	if len(offsets) < 2 {
		t.Fatalf("expected recent offsets, got %#v", offsets)
	}
	if offsets[0] != 8 {
		t.Fatalf("offsets[0] = %d, want 8", offsets[0])
	}
}

func TestBuildPredictedPortsAddsHistoryNeighborsBeforeWideSweep(t *testing.T) {
	resetPredictionHistoryForTest()
	t.Cleanup(resetPredictionHistoryForTest)

	obs := NatObservation{
		PublicIP:         "1.1.1.1",
		ObservedBasePort: 5000,
		ObservedInterval: 2,
		NATType:          NATTypeSymmetric,
		MappingBehavior:  NATMappingEndpointDependent,
	}
	recordPredictionSuccess(obs, "1.1.1.1:5006")
	recordPredictionSuccess(obs, "1.1.1.1:5006")

	ports := BuildPredictedPorts(obs, []int{2}, 6)
	if len(ports) < 4 {
		t.Fatalf("expected predicted ports, got %#v", ports)
	}
	if ports[0] != 5006 {
		t.Fatalf("ports[0] = %d, want 5006", ports[0])
	}
	if ports[1] != 5005 || ports[2] != 5007 {
		t.Fatalf("neighbor ports should follow exact history hit, got %#v", ports)
	}
}

func TestBuildPredictedPortsPrefersLikelyNextAfterSequentialSamples(t *testing.T) {
	obs := NatObservation{
		PublicIP:         "1.1.1.1",
		ObservedBasePort: 5000,
		ObservedInterval: 2,
		NATType:          NATTypeSymmetric,
		MappingBehavior:  NATMappingEndpointDependent,
		Samples: []ProbeSample{
			{ObservedAddr: "1.1.1.1:5000"},
			{ObservedAddr: "1.1.1.1:5002"},
			{ObservedAddr: "1.1.1.1:5004"},
		},
	}

	ports := BuildPredictedPorts(obs, []int{2}, 6)
	if len(ports) == 0 {
		t.Fatalf("expected predicted ports, got %#v", ports)
	}
	if ports[0] != 5006 {
		t.Fatalf("ports[0] = %d, want likely next 5006", ports[0])
	}
}

func TestPortMappingRenewIntervalTracksLeaseLifetime(t *testing.T) {
	if got := portMappingRenewInterval(20); got != 10*time.Second {
		t.Fatalf("portMappingRenewInterval(20) = %s, want 10s", got)
	}
	if got := portMappingRenewInterval(5); got != 2500*time.Millisecond {
		t.Fatalf("portMappingRenewInterval(5) = %s, want 2500ms", got)
	}
	if got := portMappingRenewInterval(1); got != 750*time.Millisecond {
		t.Fatalf("portMappingRenewInterval(1) = %s, want 750ms", got)
	}
}

func TestCloseSocketsDoesNotHoldSessionLockDuringClose(t *testing.T) {
	session := &runtimeSession{}
	socket := &testPacketConn{
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000},
		onClose: func() {
			_ = session.snapshotSockets()
		},
	}
	session.sockets = []net.PacketConn{socket}

	done := make(chan struct{})
	go func() {
		session.closeSockets(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("closeSockets should not deadlock when Close re-enters runtimeSession state")
	}
	if sockets := session.snapshotSockets(); len(sockets) != 0 {
		t.Fatalf("closeSockets should clear session sockets, got %#v", sockets)
	}
}

func TestStopSocketReadLoopInterruptsWinnerReadLoop(t *testing.T) {
	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = localConn.Close() }()

	session := &runtimeSession{
		localConn:    localConn,
		sockets:      []net.PacketConn{localConn},
		readLoopDone: make(map[net.PacketConn]chan struct{}),
		cm:           NewCandidateManager(""),
		replay:       NewReplayWindow(30 * time.Second),
	}
	ctx, cancel := context.WithCancel(context.Background())
	session.startReadLoop(ctx, localConn)
	time.Sleep(20 * time.Millisecond)
	cancel()

	if ok := session.stopSocketReadLoop(localConn, 250*time.Millisecond); !ok {
		t.Fatal("stopSocketReadLoop() should unblock the read loop before handover")
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		session.mu.Lock()
		_, exists := session.readLoopDone[localConn]
		session.mu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read loop bookkeeping should be cleared after shutdown")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type testPacketConn struct {
	localAddr net.Addr
	onClose   func()
}

func (c *testPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}
func (c *testPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *testPacketConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}
func (c *testPacketConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *testPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestBuildPCPRequestMappingPacket(t *testing.T) {
	clientIP := netip.MustParseAddr("192.168.1.10")
	prevExternalIP := netip.MustParseAddr("203.0.113.20")
	packet, nonce := buildPCPRequestMappingPacket(clientIP, 12345, 54321, 7200, prevExternalIP)
	if len(packet) != 60 {
		t.Fatalf("len(packet) = %d, want 60", len(packet))
	}
	if packet[0] != pcpVersion {
		t.Fatalf("packet version = %d, want %d", packet[0], pcpVersion)
	}
	if packet[1] != pcpOpMap {
		t.Fatalf("packet opcode = %d, want %d", packet[1], pcpOpMap)
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 7200 {
		t.Fatalf("lifetime = %d, want 7200", got)
	}
	var clientIP16 [16]byte
	copy(clientIP16[:], packet[8:24])
	if got := netip.AddrFrom16(clientIP16).Unmap(); got != clientIP {
		t.Fatalf("client ip = %s, want %s", got, clientIP)
	}
	if packet[36] != pcpUDPMapping {
		t.Fatalf("protocol = %d, want %d", packet[36], pcpUDPMapping)
	}
	if string(packet[24:36]) != string(nonce[:]) {
		t.Fatal("request nonce should be embedded in packet")
	}
	if got := binary.BigEndian.Uint16(packet[40:42]); got != 12345 {
		t.Fatalf("local port = %d, want 12345", got)
	}
	if got := binary.BigEndian.Uint16(packet[42:44]); got != 54321 {
		t.Fatalf("previous external port = %d, want 54321", got)
	}
	var externalIP16 [16]byte
	copy(externalIP16[:], packet[44:60])
	if got := netip.AddrFrom16(externalIP16).Unmap(); got != prevExternalIP {
		t.Fatalf("previous external ip = %s, want %s", got, prevExternalIP)
	}
}

func TestParsePCPMapResponse(t *testing.T) {
	response := make([]byte, 60)
	response[0] = pcpVersion
	response[1] = pcpOpMap | pcpOpReply
	response[3] = byte(pcpCodeOK)
	binary.BigEndian.PutUint32(response[4:8], 3600)
	binary.BigEndian.PutUint32(response[8:12], 42)
	var nonce [12]byte
	copy(nonce[:], "pcpnonce1234")
	copy(response[24:36], nonce[:])
	binary.BigEndian.PutUint16(response[42:44], 54321)
	externalIP := netip.MustParseAddr("198.51.100.25").As16()
	copy(response[44:60], externalIP[:])

	parsed, err := parsePCPMapResponse(response, nonce)
	if err != nil {
		t.Fatalf("parsePCPMapResponse() error = %v", err)
	}
	if parsed.ResultCode != pcpCodeOK {
		t.Fatalf("ResultCode = %s, want %s", parsed.ResultCode, pcpCodeOK)
	}
	if parsed.LifetimeSecs != 3600 {
		t.Fatalf("LifetimeSecs = %d, want 3600", parsed.LifetimeSecs)
	}
	if parsed.Epoch != 42 {
		t.Fatalf("Epoch = %d, want 42", parsed.Epoch)
	}
	if parsed.ExternalAddr != netip.MustParseAddrPort("198.51.100.25:54321") {
		t.Fatalf("ExternalAddr = %s, want 198.51.100.25:54321", parsed.ExternalAddr)
	}
}

func TestParsePCPMapResponseRejectsNonOKCodes(t *testing.T) {
	response := make([]byte, 60)
	response[0] = pcpVersion
	response[1] = pcpOpMap | pcpOpReply
	response[3] = byte(pcpCodeNotAuthorized)
	if _, err := parsePCPMapResponse(response, [12]byte{}); err == nil {
		t.Fatal("parsePCPMapResponse() should reject non-OK response codes")
	}
}

func TestParsePCPMapResponseRejectsNonceMismatch(t *testing.T) {
	response := make([]byte, 60)
	response[0] = pcpVersion
	response[1] = pcpOpMap | pcpOpReply
	response[3] = byte(pcpCodeOK)
	copy(response[24:36], "pcpnonce1234")
	binary.BigEndian.PutUint16(response[42:44], 54321)
	externalIP := netip.MustParseAddr("198.51.100.25").As16()
	copy(response[44:60], externalIP[:])

	if _, err := parsePCPMapResponse(response, [12]byte{'w', 'r', 'o', 'n', 'g'}); err == nil {
		t.Fatal("parsePCPMapResponse() should reject nonce mismatch")
	}
}

func buildFakeSTUNBindingResponse(request []byte, addr *net.UDPAddr) ([]byte, error) {
	return buildFakeSTUNBindingResponseWithAttrs(request, addr, nil, nil)
}

func buildFakeSTUNBindingResponseWithAttrs(request []byte, addr, responseOrigin, otherAddr *net.UDPAddr) ([]byte, error) {
	message := new(pionstun.Message)
	if err := message.UnmarshalBinary(request); err != nil {
		return nil, err
	}
	setters := []pionstun.Setter{
		pionstun.NewTransactionIDSetter(message.TransactionID),
		pionstun.BindingSuccess,
		&pionstun.XORMappedAddress{
			IP:   addr.IP,
			Port: addr.Port,
		},
	}
	if responseOrigin != nil {
		setters = append(setters, &pionstun.ResponseOrigin{
			IP:   responseOrigin.IP,
			Port: responseOrigin.Port,
		})
	}
	if otherAddr != nil {
		setters = append(setters, &pionstun.OtherAddress{
			IP:   otherAddr.IP,
			Port: otherAddr.Port,
		})
	}
	setters = append(setters, pionstun.Fingerprint)
	response, err := pionstun.Build(setters...)
	if err != nil {
		return nil, err
	}
	return response.Raw, nil
}
