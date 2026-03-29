package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
)

type SessionEndpoints struct {
	RendezvousRemote string
	CandidateRemote  string
	ConfirmedRemote  string
}

type confirmedPair struct {
	owner      *runtimeSession
	conn       net.PacketConn
	localAddr  string
	remoteAddr string
}

type outboundNominationState struct {
	key       string
	epoch     uint32
	startedAt time.Time
}

type inboundProposalState struct {
	key   string
	epoch uint32
}

type runtimeSession struct {
	start     P2PPunchStart
	summary   P2PProbeSummary
	plan      PunchPlan
	control   *conn.Conn
	localConn net.PacketConn
	sockets   []net.PacketConn
	cm        *CandidateManager
	ranker    *CandidateRanker
	pacer     *sessionPacer
	replay    *ReplayWindow

	mu                  sync.Mutex
	readLoopDone        map[net.PacketConn]chan struct{}
	resolvedTargetAddrs map[string]*net.UDPAddr
	endpoints           SessionEndpoints
	confirmed           chan confirmedPair
	nominate            map[string]struct{}
	accept              map[string]struct{}
	outboundNomination  outboundNominationState
	inboundProposal     inboundProposalState
	nextNominationEpoch uint32
	nominationScheduled bool
	stats               sessionStats
}

type sessionStats struct {
	tokenMismatchDropped int
	tokenVerified        bool
	replayDropped        int
}

func (s *runtimeSession) snapshotStats() sessionStats {
	if s == nil {
		return sessionStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func RunVisitorSession(ctx context.Context, control *conn.Conn, localAddr, transportMode, transportData string, defaultSTUNServers []string) (net.PacketConn, string, string, string, string, string, string, time.Duration, error) {
	start, err := ReadBridgeJSON[P2PPunchStart](control, common.P2P_PUNCH_START)
	if err != nil {
		return nil, "", "", "", "", "", "", 0, err
	}
	return runBridgeSession(ctx, control, start, localAddr, transportMode, transportData, defaultSTUNServers)
}

func RunProviderSession(ctx context.Context, control *conn.Conn, start P2PPunchStart, localAddr, transportMode, transportData string, defaultSTUNServers []string) (net.PacketConn, string, string, string, string, string, string, time.Duration, error) {
	return runBridgeSession(ctx, control, start, localAddr, transportMode, transportData, defaultSTUNServers)
}

type probeRuntimeFamily struct {
	family      udpAddrFamily
	conn        net.PacketConn
	observation NatObservation
	localAddrs  []string
}

type runtimeFamilyWorker struct {
	family  udpAddrFamily
	rs      *runtimeSession
	cancel  context.CancelFunc
	summary P2PProbeSummary
}

func runBridgeSession(ctx context.Context, control *conn.Conn, start P2PPunchStart, localAddr, transportMode, transportData string, defaultSTUNServers []string) (net.PacketConn, string, string, string, string, string, string, time.Duration, error) {
	start = NormalizeP2PPunchStart(start)
	start.Probe = WithDefaultSTUNEndpoints(start.Probe, defaultSTUNServers)
	_ = trySendProgress(control, start.SessionID, start.Role, "probe_started", "")
	families, err := openProbeRuntimeFamilies(ctx, localAddr, start)
	if err != nil {
		_ = trySendProgressWithStatus(control, start.SessionID, start.Role, "probe_failed", "fail", err.Error(), localAddr, "", nil, nil)
		_ = trySendAbort(control, start.SessionID, start.Role, fmt.Sprintf("probe failed: %v", err))
		return nil, "", "", "", "", "", "", 0, err
	}
	defer func() {
		if err == nil {
			return
		}
		for _, family := range families {
			if family.conn != nil {
				_ = family.conn.Close()
			}
		}
	}()

	selfFamilies := make([]P2PFamilyInfo, 0, len(families))
	for _, family := range families {
		selfFamilies = append(selfFamilies, P2PFamilyInfo{
			Family:     family.family.String(),
			Nat:        family.observation,
			LocalAddrs: family.localAddrs,
		})
	}
	self := BuildPeerInfo(start.Role, transportMode, transportData, selfFamilies)
	report := P2PProbeReport{
		SessionID: start.SessionID,
		Token:     start.Token,
		Role:      start.Role,
		PeerRole:  start.PeerRole,
		Self:      self,
	}
	_ = trySendProgress(control, start.SessionID, start.Role, "probe_completed", self.Nat.NATType)
	if err = WriteBridgeMessage(control, common.P2P_PROBE_REPORT, report); err != nil {
		return nil, "", "", "", "", "", "", 0, err
	}
	_ = trySendProgress(control, start.SessionID, start.Role, "probe_reported", "")

	summary, err := ReadBridgeJSON[P2PProbeSummary](control, common.P2P_PROBE_SUMMARY)
	if err != nil {
		return nil, "", "", "", "", "", "", 0, err
	}
	_ = trySendProgress(control, start.SessionID, start.Role, "summary_received", summary.Peer.Nat.NATType)
	workers, err := buildRuntimeFamilyWorkers(start, summary, control, families)
	if err != nil {
		_ = trySendProgressWithStatus(control, start.SessionID, start.Role, "family_select_failed", "fail", err.Error(), "", "", nil, nil)
		_ = trySendAbort(control, start.SessionID, start.Role, err.Error())
		return nil, "", "", "", "", "", "", 0, err
	}
	defer func() {
		if err == nil {
			return
		}
		for _, worker := range workers {
			if worker.cancel != nil {
				worker.cancel()
			}
			worker.rs.closeSockets(nil)
		}
	}()

	var primaryLocalAddr string
	if len(workers) > 0 {
		primaryLocalAddr = addrString(workers[0].rs.localConn.LocalAddr())
	}
	handshakeTimeout := time.Duration(summary.Timeouts.HandshakeTimeoutMs) * time.Millisecond
	if handshakeTimeout <= 0 {
		handshakeTimeout = 20 * time.Second
	}
	punchCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err = WriteBridgeMessage(control, common.P2P_PUNCH_READY, P2PPunchReady{
		SessionID: start.SessionID,
		Role:      start.Role,
	}); err != nil {
		return nil, "", "", "", "", "", "", 0, err
	}
	goMsg, err := ReadBridgeJSON[P2PPunchGo](control, common.P2P_PUNCH_GO)
	if err != nil {
		return nil, "", "", "", "", "", "", 0, err
	}
	if goMsg.DelayMs > 0 {
		_ = trySendProgressWithStatus(control, start.SessionID, start.Role, "punch_go_wait", "ok", fmt.Sprintf("%dms", goMsg.DelayMs), primaryLocalAddr, "", nil, nil)
		if !sleepContext(punchCtx, time.Duration(goMsg.DelayMs)*time.Millisecond) {
			err = mapP2PContextError(punchCtx.Err())
			return nil, "", "", "", "", "", "", 0, err
		}
	}
	_ = trySendProgressWithStatus(control, start.SessionID, start.Role, "punch_go", "ok", "", primaryLocalAddr, "", nil, nil)
	for _, worker := range workers {
		workerCtx, workerCancel := context.WithCancel(punchCtx)
		worker.cancel = workerCancel
		worker.rs.startReadLoop(workerCtx, worker.rs.localConn)
		go worker.rs.candidateMaintenanceLoop(workerCtx)
		go worker.rs.startSpray(workerCtx)
	}
	transportTimeout := time.Duration(summary.Timeouts.TransportTimeoutMs) * time.Millisecond
	if transportTimeout <= 0 {
		transportTimeout = 10 * time.Second
	}

	select {
	case pair := <-workers[0].rs.confirmed:
		winner := workerForConfirmedPair(workers, pair)
		for _, worker := range workers {
			if worker.cancel != nil {
				worker.cancel()
			}
			if winner == nil || worker != winner {
				worker.rs.closeSockets(nil)
			}
		}
		if winner == nil {
			err = fmt.Errorf("confirmed pair missing family worker")
			return nil, "", "", "", "", "", "", 0, err
		}
		if !winner.rs.stopSocketReadLoop(pair.conn, 300*time.Millisecond) {
			logs.Warn("[P2P] handover read loop did not stop promptly role=%s family=%s local=%s remote=%s",
				start.Role, winner.family.String(), pair.localAddr, pair.remoteAddr)
		}
		mode := negotiateTransportMode(transportMode, winner.summary.Peer.TransportMode)
		winner.rs.closeSockets(pair.conn)
		_ = winner.rs.sendProgress("candidate_confirmed", "ok", pair.remoteAddr, pair.localAddr, pair.remoteAddr, nil)
		_ = winner.rs.sendProgress("handover_begin", "ok", mode, pair.localAddr, pair.remoteAddr, map[string]string{
			"transport_mode": mode,
			"family":         winner.family.String(),
		})
		recordPredictionSuccess(winner.summary.Peer.Nat, pair.remoteAddr)
		recordAdaptiveProfileSuccess(winner.summary, mode)
		winner.rs.logTokenStats()
		logs.Info("[P2P] handover begin role=%s family=%s confirmed pair=%s local=%s transport=%s", start.Role, winner.family.String(), pair.remoteAddr, pair.localAddr, mode)
		return pair.conn, pair.remoteAddr, pair.localAddr, start.SessionID, start.Role, mode, winner.summary.Peer.TransportData, transportTimeout, nil
	case <-punchCtx.Done():
		err = mapP2PContextError(punchCtx.Err())
		for _, worker := range workers {
			recordAdaptiveProfileTimeout(worker.summary)
			_ = worker.rs.sendProgress("handshake_timeout", "fail", err.Error(), addrString(worker.rs.localConn.LocalAddr()), worker.rs.cm.CandidateRemote(), nil)
			worker.rs.logTokenStats()
		}
		_ = trySendAbort(control, start.SessionID, start.Role, err.Error())
		return nil, "", "", "", "", "", "", 0, err
	}
}

func openProbeRuntimeFamilies(ctx context.Context, preferredLocalAddr string, start P2PPunchStart) ([]probeRuntimeFamily, error) {
	localAddrs, err := ChooseLocalProbeAddrs(preferredLocalAddr, start.Probe)
	if err != nil {
		return nil, err
	}
	type probeResult struct {
		index  int
		family probeRuntimeFamily
		err    string
	}
	results := make(chan probeResult, len(localAddrs))
	var wg sync.WaitGroup
	for index, bindAddr := range localAddrs {
		wg.Add(1)
		go func(index int, bindAddr string) {
			defer wg.Done()
			localConn, err := conn.NewUdpConnByAddr(bindAddr)
			if err != nil {
				results <- probeResult{index: index, err: err.Error()}
				return
			}
			portMappingConn := localConn
			var portMapping *PortMappingInfo
			if detectAddrFamily(localConn.LocalAddr()) == udpFamilyV4 {
				portMappingConn, portMapping = maybeEnablePortMapping(ctx, localConn, start.Probe)
			}
			observation, err := runProbe(ctx, portMappingConn, start)
			if err != nil {
				_ = portMappingConn.Close()
				results <- probeResult{index: index, err: err.Error()}
				return
			}
			if portMapping != nil {
				observation.PortMapping = portMapping
			}
			results <- probeResult{
				index: index,
				family: probeRuntimeFamily{
					family:      detectAddrFamily(portMappingConn.LocalAddr()),
					conn:        portMappingConn,
					observation: observation,
					localAddrs:  buildLocalAddrs(portMappingConn.LocalAddr()),
				},
			}
		}(index, bindAddr)
	}
	wg.Wait()
	close(results)

	ordered := make([]probeResult, 0, len(localAddrs))
	for result := range results {
		ordered = append(ordered, result)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })

	families := make([]probeRuntimeFamily, 0, len(localAddrs))
	errs := make([]string, 0, len(localAddrs))
	for _, result := range ordered {
		if result.err != "" {
			errs = append(errs, result.err)
			continue
		}
		families = append(families, result.family)
	}
	if len(families) == 0 {
		if len(errs) == 0 {
			return nil, fmt.Errorf("no usable local probe family")
		}
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return families, nil
}

func buildRuntimeFamilyWorkers(start P2PPunchStart, summary P2PProbeSummary, control *conn.Conn, families []probeRuntimeFamily) ([]*runtimeFamilyWorker, error) {
	if len(families) == 0 {
		return nil, fmt.Errorf("empty local probe families")
	}
	confirmed := make(chan confirmedPair, 1)
	workers := make([]*runtimeFamilyWorker, 0, len(families))
	for _, family := range families {
		selfInfo, ok := PeerInfoForFamily(summary.Self, family.family)
		if !ok {
			continue
		}
		peerInfo, ok := PeerInfoForFamily(summary.Peer, family.family)
		if !ok {
			continue
		}
		familySummary := summary
		familySummary.Self = selfInfo
		familySummary.Peer = peerInfo
		plan := ApplyProbePlanOptions(SelectPunchPlan(familySummary.Self, familySummary.Peer, familySummary.Timeouts), start.Probe, familySummary.Self, familySummary.Peer)
		plan = ApplySummaryHintsToPlan(plan, familySummary)
		logs.Info("[P2P] selected PunchPlan role=%s family=%s mappingConfidenceLow=%v probePortRestricted=%v prediction=%v targetSpray=%v birthday=%v birthdayFallback=%v intervals=%v timeout=%s",
			start.Role, family.family.String(), familySummary.Self.Nat.MappingConfidenceLow, familySummary.Self.Nat.ProbePortRestricted,
			plan.EnablePrediction, plan.UseTargetSpray, plan.UseBirthdayAttack, plan.AllowBirthdayFallback, plan.predictionIntervals(), plan.HandshakeTimeout)
		workers = append(workers, &runtimeFamilyWorker{
			family:  family.family,
			rs:      newRuntimeSession(start, familySummary, plan, control, family.conn, confirmed),
			summary: familySummary,
		})
	}
	if len(workers) == 0 {
		return nil, fmt.Errorf("no compatible punch family between peers")
	}
	sortRuntimeFamilyWorkers(workers)
	for _, worker := range workers {
		profileScore := adaptiveProfileScore(worker.summary)
		_ = worker.rs.sendProgress("family_ready", "ok", "", addrString(worker.rs.localConn.LocalAddr()), firstObservedAddr(worker.summary.Peer), map[string]string{
			"family":                 worker.family.String(),
			"nat_type":               worker.summary.Self.Nat.NATType,
			"mapping_behavior":       worker.summary.Self.Nat.MappingBehavior,
			"filtering_behavior":     worker.summary.Self.Nat.FilteringBehavior,
			"classification_level":   worker.summary.Self.Nat.ClassificationLevel,
			"prediction":             strconv.FormatBool(worker.rs.plan.EnablePrediction),
			"target_spray":           strconv.FormatBool(worker.rs.plan.UseTargetSpray),
			"birthday":               strconv.FormatBool(worker.rs.plan.UseBirthdayAttack),
			"birthday_fallback":      strconv.FormatBool(worker.rs.plan.AllowBirthdayFallback),
			"handshake_timeout_ms":   strconv.FormatInt(worker.rs.plan.HandshakeTimeout.Milliseconds(), 10),
			"transport_timeout_ms":   strconv.Itoa(worker.summary.Timeouts.TransportTimeoutMs),
			"probe_endpoint_count":   strconv.Itoa(worker.summary.Self.Nat.ProbeEndpointCount),
			"probe_provider_count":   strconv.Itoa(probeSampleProviderCount(worker.summary.Self.Nat.Samples)),
			"mapping_confidence_low": strconv.FormatBool(worker.summary.Self.Nat.MappingConfidenceLow),
			"adaptive_profile_score": strconv.Itoa(profileScore),
		})
	}
	return workers, nil
}

func sortRuntimeFamilyWorkers(workers []*runtimeFamilyWorker) {
	sort.SliceStable(workers, func(i, j int) bool {
		left := workers[i]
		right := workers[j]
		if left == nil || left.rs == nil {
			return false
		}
		if right == nil || right.rs == nil {
			return true
		}
		leftScore := adaptiveProfileScore(left.summary)
		rightScore := adaptiveProfileScore(right.summary)
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		if left.summary.Self.Nat.MappingConfidenceLow != right.summary.Self.Nat.MappingConfidenceLow {
			return !left.summary.Self.Nat.MappingConfidenceLow
		}
		return left.family < right.family
	})
}

func probeSampleProviderCount(samples []ProbeSample) int {
	if len(samples) == 0 {
		return 0
	}
	providers := make(map[string]struct{}, len(samples))
	for _, sample := range samples {
		provider := sample.Provider
		if provider == "" {
			provider = ProbeProviderNPS
		}
		providers[provider] = struct{}{}
	}
	return len(providers)
}

func newRuntimeSession(start P2PPunchStart, summary P2PProbeSummary, plan PunchPlan, control *conn.Conn, localConn net.PacketConn, confirmed chan confirmedPair) *runtimeSession {
	rs := &runtimeSession{
		start:        start,
		summary:      summary,
		plan:         plan,
		control:      control,
		localConn:    localConn,
		sockets:      []net.PacketConn{localConn},
		cm:           NewCandidateManager(firstObservedAddr(summary.Peer)),
		ranker:       NewCandidateRanker(summary.Self, summary.Peer, plan),
		pacer:        newSessionPacer(start),
		replay:       NewReplayWindow(30 * time.Second),
		readLoopDone: make(map[net.PacketConn]chan struct{}),
		confirmed:    confirmed,
		nominate:     make(map[string]struct{}),
		accept:       make(map[string]struct{}),
	}
	rs.endpoints.RendezvousRemote = firstObservedAddr(summary.Peer)
	return rs
}

func workerForConfirmedPair(workers []*runtimeFamilyWorker, pair confirmedPair) *runtimeFamilyWorker {
	for _, worker := range workers {
		if worker == nil || worker.rs == nil {
			continue
		}
		if pair.owner != nil && worker.rs == pair.owner {
			return worker
		}
		if pair.conn != nil && worker.rs.ownsSocket(pair.conn) {
			return worker
		}
	}
	return nil
}

func runProbe(ctx context.Context, localConn net.PacketConn, start P2PPunchStart) (NatObservation, error) {
	endpoints := NormalizeProbeEndpoints(start.Probe)
	if len(endpoints) == 0 {
		return NatObservation{}, fmt.Errorf("empty probe endpoints")
	}
	stunEndpoints := make([]P2PProbeEndpoint, 0, len(endpoints))
	npsEndpoints := make([]P2PProbeEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		switch {
		case endpoint.Provider == ProbeProviderSTUN && endpoint.Mode == ProbeModeBinding && endpoint.Network == ProbeNetworkUDP:
			stunEndpoints = append(stunEndpoints, endpoint)
		case endpoint.Provider == ProbeProviderNPS && endpoint.Mode == ProbeModeUDP && endpoint.Network == ProbeNetworkUDP:
			npsEndpoints = append(npsEndpoints, endpoint)
		default:
			logs.Trace("[P2P] skip unsupported probe endpoint provider=%s mode=%s network=%s address=%s", endpoint.Provider, endpoint.Mode, endpoint.Network, endpoint.Address)
		}
	}
	if len(stunEndpoints) == 0 && len(npsEndpoints) == 0 {
		return NatObservation{}, fmt.Errorf("unsupported probe configuration provider=%s mode=%s network=%s", start.Probe.Provider, start.Probe.Mode, start.Probe.Network)
	}

	samples := make([]ProbeSample, 0, len(endpoints))
	var sawExtraReply bool
	var npsSucceeded bool
	if len(stunEndpoints) > 0 {
		stunSamples, err := runSTUNProbes(ctx, localConn, stunEndpoints, start.Timeouts.ProbeTimeoutMs)
		if err != nil {
			logs.Trace("[P2P] stun calibration unavailable err=%v", err)
		} else if len(stunSamples) > 0 {
			for _, sample := range stunSamples {
				logs.Info("[P2P] stun calibration success endpoint=%s observed=%s", sample.EndpointID, sample.ObservedAddr)
			}
			samples = append(samples, stunSamples...)
		}
	}
	if len(npsEndpoints) > 0 {
		npsSamples, extraReplySeen, err := runNPSProbe(ctx, localConn, start, npsEndpoints)
		if err != nil {
			logs.Trace("[P2P] nps probe unavailable err=%v", err)
		} else {
			samples = append(samples, npsSamples...)
			sawExtraReply = extraReplySeen
			npsSucceeded = len(npsSamples) > 0
		}
	}
	if len(samples) == 0 {
		return NatObservation{}, fmt.Errorf("no successful probe endpoints for %s", addrString(localConn.LocalAddr()))
	}
	filteringTested := start.Probe.ExpectExtraReply && npsSucceeded
	return BuildNatObservationWithEvidence(samples, sawExtraReply, filteringTested), nil
}

func runNPSProbe(ctx context.Context, localConn net.PacketConn, start P2PPunchStart, endpoints []P2PProbeEndpoint) ([]ProbeSample, bool, error) {
	endpoints = compatibleNPSProbeEndpoints(localConn.LocalAddr(), endpoints)
	if len(endpoints) == 0 {
		return nil, false, fmt.Errorf("no compatible nps probe endpoints for %s", addrString(localConn.LocalAddr()))
	}
	type resolvedProbeEndpoint struct {
		endpoint P2PProbeEndpoint
		addr     *net.UDPAddr
		key      string
	}
	resolvedEndpoints := make([]resolvedProbeEndpoint, 0, len(endpoints))
	seenResolved := make(map[string]struct{}, len(endpoints))
	resolveTimeout := 250 * time.Millisecond
	if start.Timeouts.ProbeTimeoutMs > 0 {
		timeout := time.Duration(start.Timeouts.ProbeTimeoutMs) * time.Millisecond / 4
		if timeout > 0 && timeout < resolveTimeout {
			resolveTimeout = timeout
		}
	}
	for _, endpoint := range endpoints {
		udpAddr, err := resolveUDPAddrContext(ctx, localConn.LocalAddr(), endpoint.Address, resolveTimeout)
		if err != nil {
			continue
		}
		key := npsProbeKey(common.GetPortByAddr(endpoint.Address), udpAddr.String())
		if key == "" {
			continue
		}
		if _, ok := seenResolved[key]; ok {
			continue
		}
		seenResolved[key] = struct{}{}
		resolvedEndpoints = append(resolvedEndpoints, resolvedProbeEndpoint{
			endpoint: endpoint,
			addr:     udpAddr,
			key:      key,
		})
	}
	if len(resolvedEndpoints) == 0 {
		return nil, false, fmt.Errorf("no resolvable nps probe endpoints for %s", addrString(localConn.LocalAddr()))
	}
	expectedKeys := make(map[string]struct{}, len(resolvedEndpoints))
	for _, endpoint := range resolvedEndpoints {
		expectedKeys[endpoint.key] = struct{}{}
	}
	if len(expectedKeys) == 0 {
		return nil, false, fmt.Errorf("no valid nps probe endpoints for %s", addrString(localConn.LocalAddr()))
	}
	samples := make(map[string]ProbeSample, len(expectedKeys))
	var extraReplySeen bool
	buf := common.BufPoolUdp.Get()
	defer common.BufPoolUdp.Put(buf)

	sendProbe := func() {
		for _, endpoint := range resolvedEndpoints {
			packet := newUDPPacketWithWire(start.SessionID, start.Token, start.Role, packetTypeProbe, p2pStartWireSpec(start))
			packet.ProbePort = common.GetPortByAddr(endpoint.endpoint.Address)
			raw, err := EncodeUDPPacket(packet)
			if err != nil {
				continue
			}
			_, _ = localConn.WriteTo(raw, endpoint.addr)
		}
	}

	sendProbe()
	deadline := time.Now().Add(time.Duration(start.Timeouts.ProbeTimeoutMs) * time.Millisecond)
	if start.Timeouts.ProbeTimeoutMs <= 0 {
		deadline = time.Now().Add(5 * time.Second)
	}
	for time.Now().Before(deadline) {
		if len(samples) >= len(expectedKeys) && (!start.Probe.ExpectExtraReply || extraReplySeen) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, false, mapP2PContextError(ctx.Err())
		default:
		}
		_ = localConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, replyAddr, err := localConn.ReadFrom(buf)
		_ = localConn.SetReadDeadline(time.Time{})
		if err != nil {
			if conn.IsTimeout(err) {
				sendProbe()
				continue
			}
			if isIgnorableUDPIcmpError(err) {
				continue
			}
			return nil, false, err
		}
		packet, err := DecodeUDPPacket(buf[:n], start.Token)
		if err != nil {
			continue
		}
		if packet.SessionID != start.SessionID || packet.Token != start.Token || !SameWireRoute(packet.WireID, p2pStartWireSpec(start).RouteID) {
			continue
		}
		if packet.Type != packetTypeAck && packet.Type != packetTypeProbeX {
			continue
		}
		sample := ProbeSample{
			Provider:        ProbeProviderNPS,
			Mode:            ProbeModeUDP,
			ProbePort:       packet.ProbePort,
			ObservedAddr:    packet.ObservedAddr,
			ServerReplyAddr: replyAddr.String(),
			ExtraReply:      packet.ExtraReply || packet.Type == packetTypeProbeX,
		}
		if sample.ExtraReply {
			extraReplySeen = true
		}
		if key := npsProbeSampleKey(sample); key != "" && sample.ObservedAddr != "" {
			if existing, ok := samples[key]; ok {
				if existing.ObservedAddr == "" {
					existing.ObservedAddr = sample.ObservedAddr
				}
				if existing.ServerReplyAddr == "" || !sample.ExtraReply {
					existing.ServerReplyAddr = sample.ServerReplyAddr
				}
				existing.ExtraReply = existing.ExtraReply || sample.ExtraReply
				samples[key] = existing
			} else {
				samples[key] = sample
			}
		}
	}
	out := make([]ProbeSample, 0, len(samples))
	for _, sample := range samples {
		out = append(out, sample)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProbePort != out[j].ProbePort {
			return out[i].ProbePort < out[j].ProbePort
		}
		return out[i].ServerReplyAddr < out[j].ServerReplyAddr
	})
	return out, extraReplySeen, nil
}

func npsProbeSampleKey(sample ProbeSample) string {
	return npsProbeKey(sample.ProbePort, sample.ServerReplyAddr)
}

func npsProbeKey(probePort int, addr string) string {
	replyIP := probeSampleReplyIP(addr)
	if probePort <= 0 || replyIP == "" {
		return ""
	}
	return fmt.Sprintf("%d|%s", probePort, replyIP)
}

func compatibleNPSProbeEndpoints(localAddr net.Addr, endpoints []P2PProbeEndpoint) []P2PProbeEndpoint {
	localIP := common.ParseIPFromAddr(addrString(localAddr))
	if localIP == nil {
		return append([]P2PProbeEndpoint(nil), endpoints...)
	}
	wantIPv6 := localIP.To4() == nil
	out := make([]P2PProbeEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		host := common.GetIpByAddr(endpoint.Address)
		ip := net.ParseIP(host)
		if ip != nil && (ip.To4() == nil) != wantIPv6 {
			continue
		}
		out = append(out, endpoint)
	}
	return out
}

func probeResolveNetwork(localAddr net.Addr) string {
	return detectAddrFamily(localAddr).network()
}

func buildLocalAddrs(localAddr net.Addr) []string {
	out := make([]string, 0, 8)
	port := ""
	if localAddr != nil {
		port = common.GetPortStrByAddr(localAddr.String())
	}
	add := func(ip net.IP) {
		if ip == nil || port == "" {
			return
		}
		addr := net.JoinHostPort(ip.String(), port)
		if addr == "" {
			return
		}
		for _, existing := range out {
			if existing == addr {
				return
			}
		}
		out = append(out, addr)
	}
	if ip := common.ParseIPFromAddr(addrString(localAddr)); ip != nil {
		add(ip)
	}
	if udp4, err := common.GetLocalUdp4IP(); err == nil {
		add(udp4)
	}
	if udp6, err := common.GetLocalUdp6IP(); err == nil {
		add(udp6)
	}
	for _, ip := range listInterfaceIPs() {
		add(ip)
	}
	return out
}

func (s *runtimeSession) startReadLoop(ctx context.Context, readConn net.PacketConn) {
	if s == nil || readConn == nil {
		return
	}
	done := make(chan struct{})
	s.mu.Lock()
	if s.readLoopDone == nil {
		s.readLoopDone = make(map[net.PacketConn]chan struct{})
	}
	if _, exists := s.readLoopDone[readConn]; exists {
		s.mu.Unlock()
		return
	}
	s.readLoopDone[readConn] = done
	s.mu.Unlock()

	go func() {
		defer s.finishReadLoop(readConn, done)
		s.readLoopOnConn(ctx, readConn)
	}()
}

func (s *runtimeSession) finishReadLoop(readConn net.PacketConn, done chan struct{}) {
	if done != nil {
		close(done)
	}
	if s == nil || readConn == nil {
		return
	}
	s.mu.Lock()
	if current, ok := s.readLoopDone[readConn]; ok && current == done {
		delete(s.readLoopDone, readConn)
	}
	s.mu.Unlock()
}

func (s *runtimeSession) stopSocketReadLoop(readConn net.PacketConn, timeout time.Duration) bool {
	if s == nil || readConn == nil {
		return true
	}
	s.mu.Lock()
	done := s.readLoopDone[readConn]
	s.mu.Unlock()
	if done == nil {
		return true
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	_ = readConn.SetReadDeadline(time.Now())
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	defer func() {
		_ = readConn.SetReadDeadline(time.Time{})
	}()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func listInterfaceIPs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]net.IP, 0, 8)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			ip = common.NormalizeIP(ip)
			if ip == nil || common.IsZeroIP(ip) || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func firstObservedAddr(peer P2PPeerInfo) string {
	for _, sample := range peer.Nat.Samples {
		if addr := common.ValidateAddr(sample.ObservedAddr); addr != "" {
			return addr
		}
	}
	if peer.Nat.PublicIP != "" && peer.Nat.ObservedBasePort > 0 {
		return net.JoinHostPort(peer.Nat.PublicIP, fmt.Sprintf("%d", peer.Nat.ObservedBasePort))
	}
	return ""
}

func negotiateTransportMode(selfMode, peerMode string) string {
	selfMode = strings.TrimSpace(selfMode)
	peerMode = strings.TrimSpace(peerMode)
	if selfMode == "" {
		selfMode = common.CONN_KCP
	}
	if peerMode == "" {
		peerMode = selfMode
	}
	if selfMode == peerMode {
		return selfMode
	}
	return common.CONN_KCP
}

func ChooseLocalProbeAddr(probe P2PProbeConfig) (string, error) {
	addrs, err := ChooseLocalProbeAddrs("", probe)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}

func ChooseLocalProbeAddrs(preferredAddr string, probe P2PProbeConfig) ([]string, error) {
	type localCandidate struct {
		family udpAddrFamily
		addr   string
	}
	familyCandidates := make(map[udpAddrFamily]string, 2)
	setCandidate := func(addr string) {
		addr = normalizeLocalProbeCandidate(addr)
		if addr == "" {
			return
		}
		family := detectAddressFamily(addr)
		if family == udpFamilyAny {
			return
		}
		familyCandidates[family] = addr
	}
	if addr, err := common.GetLocalUdp4Addr(); err == nil {
		setCandidate(addr.String())
	}
	if addr, err := common.GetLocalUdp6Addr(); err == nil {
		setCandidate(addr.String())
	}
	if len(familyCandidates) == 0 {
		return nil, fmt.Errorf("no local udp probe address available")
	}

	resolveTimeout := 250 * time.Millisecond
	if probeTimeoutMs, ok := parseProbeIntOption(probe.Options, "probe_timeout_ms"); ok && probeTimeoutMs > 0 {
		timeout := time.Duration(probeTimeoutMs) * time.Millisecond / 4
		if timeout > 0 && timeout < resolveTimeout {
			resolveTimeout = timeout
		}
	}
	resolveCtx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()

	type familyScore struct {
		nps   int
		stun  int
		total int
	}
	scores := map[udpAddrFamily]familyScore{
		udpFamilyV4: {},
		udpFamilyV6: {},
	}
	for _, endpoint := range NormalizeProbeEndpoints(probe) {
		families := probeEndpointFamilies(resolveCtx, endpoint, resolveTimeout)
		for _, family := range families {
			score := scores[family]
			score.total++
			if endpoint.Provider == ProbeProviderSTUN {
				score.stun++
			} else {
				score.nps++
			}
			scores[family] = score
		}
	}

	if bindAddr, family, ok := preferredProbeBindAddr(preferredAddr); ok && scores[family].total > 0 {
		familyCandidates[family] = bindAddr
	}

	candidates := make([]localCandidate, 0, len(familyCandidates))
	for family, addr := range familyCandidates {
		if scores[family].total == 0 {
			continue
		}
		candidates = append(candidates, localCandidate{
			family: family,
			addr:   addr,
		})
	}
	if len(candidates) == 0 {
		for family, addr := range familyCandidates {
			candidates = append(candidates, localCandidate{
				family: family,
				addr:   addr,
			})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		leftScore := scores[left.family]
		rightScore := scores[right.family]
		leftHasNPS := leftScore.nps > 0
		rightHasNPS := rightScore.nps > 0
		switch {
		case leftHasNPS != rightHasNPS:
			return leftHasNPS
		case leftScore.nps != rightScore.nps:
			return leftScore.nps > rightScore.nps
		case leftScore.total != rightScore.total:
			return leftScore.total > rightScore.total
		case leftScore.stun != rightScore.stun:
			return leftScore.stun > rightScore.stun
		default:
			return left.family < right.family
		}
	})
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.addr)
	}
	return out, nil
}

func normalizeLocalProbeCandidate(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return ""
	}
	ip := common.NormalizeIP(udpAddr.IP)
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(udpAddr.Port))
}

func preferredProbeBindAddr(preferredAddr string) (string, udpAddrFamily, bool) {
	preferredAddr = strings.TrimSpace(preferredAddr)
	preferredAddr = strings.Trim(preferredAddr, "[]")
	if preferredAddr == "" {
		return "", udpFamilyAny, false
	}
	ip := net.ParseIP(preferredAddr)
	if ip == nil || ip.IsUnspecified() {
		return "", udpFamilyAny, false
	}
	family := detectIPFamily(ip)
	if family == udpFamilyAny {
		return "", udpFamilyAny, false
	}
	return net.JoinHostPort(ip.String(), "0"), family, true
}

func probeEndpointFamilies(ctx context.Context, endpoint P2PProbeEndpoint, timeout time.Duration) []udpAddrFamily {
	host := common.GetIpByAddr(endpoint.Address)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		family := detectIPFamily(ip)
		if family == udpFamilyAny {
			return nil
		}
		return []udpAddrFamily{family}
	}

	resolveCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		resolveCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil
	}
	families := make([]udpAddrFamily, 0, 2)
	seen := make(map[udpAddrFamily]struct{}, 2)
	for _, addr := range addrs {
		family := detectIPFamily(addr.IP)
		if family == udpFamilyAny {
			continue
		}
		if _, ok := seen[family]; ok {
			continue
		}
		seen[family] = struct{}{}
		families = append(families, family)
	}
	return families
}

func probeEndpointAddrs(probe P2PProbeConfig) []string {
	endpoints := NormalizeProbeEndpoints(probe)
	addrs := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		addr := endpoint.Address
		if endpoint.Provider == ProbeProviderSTUN {
			if host, port, err := net.SplitHostPort(addr); err == nil && host != "" && port != "" && common.GetPortByAddr(addr) > 0 {
				addrs = append(addrs, addr)
			}
			continue
		}
		if validated := common.ValidateAddr(addr); validated != "" {
			addrs = append(addrs, validated)
		}
	}
	return addrs
}

func (s *runtimeSession) addSocket(socket net.PacketConn) {
	if socket == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.sockets {
		if existing == socket {
			return
		}
	}
	s.sockets = append(s.sockets, socket)
}

func (s *runtimeSession) snapshotSockets() []net.PacketConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.PacketConn, 0, len(s.sockets))
	out = append(out, s.sockets...)
	return out
}

type resolvedPunchTarget struct {
	index int
	addr  *net.UDPAddr
}

func (s *runtimeSession) resolvePunchTargets(localAddr net.Addr, targets []string) []resolvedPunchTarget {
	if len(targets) == 0 || localAddr == nil {
		return nil
	}
	network := detectAddrFamily(localAddr).network()
	if network == "" {
		return nil
	}
	resolved := make([]resolvedPunchTarget, 0, len(targets))
	for index, target := range targets {
		addr := s.resolvePunchTarget(network, target)
		if addr == nil {
			continue
		}
		resolved = append(resolved, resolvedPunchTarget{
			index: index,
			addr:  addr,
		})
	}
	return resolved
}

func (s *runtimeSession) resolvePunchTarget(network, target string) *net.UDPAddr {
	if s == nil {
		return nil
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	key := network + "|" + target

	s.mu.Lock()
	if cached := s.resolvedTargetAddrs[key]; cached != nil {
		s.mu.Unlock()
		return cached
	}
	s.mu.Unlock()

	addr, err := net.ResolveUDPAddr(network, target)
	if err != nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resolvedTargetAddrs == nil {
		s.resolvedTargetAddrs = make(map[string]*net.UDPAddr)
	}
	if cached := s.resolvedTargetAddrs[key]; cached != nil {
		return cached
	}
	s.resolvedTargetAddrs[key] = addr
	return addr
}

func (s *runtimeSession) ownsSocket(socket net.PacketConn) bool {
	if s == nil || socket == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.sockets {
		if existing == socket {
			return true
		}
	}
	return false
}

func (s *runtimeSession) closeSockets(keep net.PacketConn) {
	s.mu.Lock()
	toClose := make([]net.PacketConn, 0, len(s.sockets))
	for _, socket := range s.sockets {
		if socket == nil || socket == keep {
			continue
		}
		toClose = append(toClose, socket)
	}
	if keep != nil {
		s.sockets = []net.PacketConn{keep}
	} else {
		s.sockets = nil
	}
	s.mu.Unlock()
	for _, socket := range toClose {
		_ = socket.Close()
	}
}

func (s *runtimeSession) enableBirthdayFallback() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plan.UseBirthdayAttack = true
}

func (s *runtimeSession) ensureRanker() *CandidateRanker {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ranker == nil {
		s.ranker = NewCandidateRanker(s.summary.Self, s.summary.Peer, s.plan)
	}
	return s.ranker
}

func (s *runtimeSession) ensurePacer() *sessionPacer {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pacer == nil {
		s.pacer = newSessionPacer(s.start)
	}
	return s.pacer
}

func (s *runtimeSession) candidateMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	maxAge := 5 * time.Second
	if s.plan.HandshakeTimeout > 0 && s.plan.HandshakeTimeout < 20*time.Second {
		maxAge = s.plan.HandshakeTimeout / 3
		if maxAge < 2*time.Second {
			maxAge = 2 * time.Second
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pruned := s.cm.PruneStale(maxAge)
			s.cm.CleanupClosed(maxAge)
			if pruned > 0 {
				_ = s.sendProgress("candidate_pruned", "ok", fmt.Sprintf("%d", pruned), addrString(s.localConn.LocalAddr()), s.cm.CandidateRemote(), map[string]string{
					"max_age_ms": fmt.Sprintf("%d", maxAge.Milliseconds()),
				})
			}
		}
	}
}
