package p2p

import (
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/djylb/nps/lib/common"
)

const (
	DefaultPredictionInterval = 1
	DefaultSpraySpan          = 64
	DefaultSprayRounds        = 2
	DefaultSprayBurst         = 8
	DefaultBirthdayPorts      = 8
	DefaultBirthdayTargets    = 16
)

type PunchPlan struct {
	EnablePrediction        bool
	UseTargetSpray          bool
	UseBirthdayAttack       bool
	AllowBirthdayFallback   bool
	PredictionInterval      int
	PredictionIntervals     []int
	HandshakeTimeout        time.Duration
	NominationDelay         time.Duration
	NominationRetryInterval time.Duration
	SpraySpan               int
	SprayRounds             int
	SprayBurst              int
	SprayPerPacketSleep     time.Duration
	SprayBurstGap           time.Duration
	SprayPhaseGap           time.Duration
	BirthdayListenPorts     int
	BirthdayTargetsPerPort  int
}

type PunchTargetStage struct {
	Name    string
	Targets []string
}

func SelectPunchPlan(self, peer P2PPeerInfo, timeouts P2PTimeouts) PunchPlan {
	selfFilteringKnown := filteringEvidenceKnown(self.Nat)
	peerFilteringKnown := filteringEvidenceKnown(peer.Nat)
	selfNPSOnly := conservativeNPSOnlyEvidence(self.Nat)
	peerNPSOnly := conservativeNPSOnlyEvidence(peer.Nat)
	enablePrediction := self.Nat.ProbePortRestricted || peer.Nat.ProbePortRestricted ||
		!selfFilteringKnown || !peerFilteringKnown ||
		self.Nat.MappingConfidenceLow || peer.Nat.MappingConfidenceLow ||
		self.Nat.NATType == NATTypeSymmetric || peer.Nat.NATType == NATTypeSymmetric ||
		selfNPSOnly || peerNPSOnly
	allowBirthdayFallback := shouldAllowBirthdayFallback(self, peer)
	intervals := BuildPredictionIntervals(peer.Nat, enablePrediction, enablePrediction)
	interval := 0
	if len(intervals) > 0 {
		interval = intervals[0]
	}
	handshakeTimeout := time.Duration(timeouts.HandshakeTimeoutMs) * time.Millisecond
	if handshakeTimeout <= 0 {
		handshakeTimeout = 20 * time.Second
	}
	plan := PunchPlan{
		EnablePrediction:        enablePrediction,
		UseTargetSpray:          enablePrediction || len(peer.Nat.Samples) == 0,
		UseBirthdayAttack:       false,
		AllowBirthdayFallback:   allowBirthdayFallback,
		PredictionInterval:      interval,
		PredictionIntervals:     intervals,
		HandshakeTimeout:        handshakeTimeout,
		NominationDelay:         120 * time.Millisecond,
		NominationRetryInterval: 300 * time.Millisecond,
		SpraySpan:               DefaultSpraySpan,
		SprayRounds:             DefaultSprayRounds,
		SprayBurst:              DefaultSprayBurst,
		SprayPerPacketSleep:     5 * time.Millisecond,
		SprayBurstGap:           10 * time.Millisecond,
		SprayPhaseGap:           40 * time.Millisecond,
		BirthdayListenPorts:     DefaultBirthdayPorts,
		BirthdayTargetsPerPort:  DefaultBirthdayTargets,
	}
	return tunePunchPlan(plan, self, peer)
}

func ApplyProbePlanOptions(plan PunchPlan, probe P2PProbeConfig, self, peer P2PPeerInfo) PunchPlan {
	if value, ok := parseProbeBoolOption(probe.Options, "force_predict_on_restricted"); ok && !value {
		if !self.Nat.MappingConfidenceLow && !peer.Nat.MappingConfidenceLow && (self.Nat.ProbePortRestricted || peer.Nat.ProbePortRestricted) {
			plan.EnablePrediction = false
			plan.PredictionInterval = 0
			if len(peer.Nat.Samples) > 0 {
				plan.UseTargetSpray = false
			}
		}
	}
	if value, ok := parseProbeBoolOption(probe.Options, "enable_target_spray"); ok {
		plan.UseTargetSpray = value
	}
	if value, ok := parseProbeIntOption(probe.Options, "default_prediction_interval"); ok && value > 0 && plan.EnablePrediction && plan.PredictionInterval == DefaultPredictionInterval {
		plan.PredictionInterval = value
		if len(plan.PredictionIntervals) == 0 {
			plan.PredictionIntervals = []int{value}
		} else {
			plan.PredictionIntervals[0] = value
		}
	}
	if value, ok := parseProbeIntOption(probe.Options, "target_spray_span"); ok && value > 0 {
		plan.SpraySpan = value
	}
	if value, ok := parseProbeIntOption(probe.Options, "target_spray_rounds"); ok && value > 0 {
		plan.SprayRounds = value
	}
	if value, ok := parseProbeIntOption(probe.Options, "target_spray_burst"); ok && value > 0 {
		plan.SprayBurst = value
	}
	if value, ok := parseProbeIntOption(probe.Options, "target_spray_packet_sleep_ms"); ok && value >= 0 {
		plan.SprayPerPacketSleep = time.Duration(value) * time.Millisecond
	}
	if value, ok := parseProbeIntOption(probe.Options, "target_spray_burst_gap_ms"); ok && value >= 0 {
		plan.SprayBurstGap = time.Duration(value) * time.Millisecond
	}
	if value, ok := parseProbeIntOption(probe.Options, "target_spray_phase_gap_ms"); ok && value >= 0 {
		plan.SprayPhaseGap = time.Duration(value) * time.Millisecond
	}
	if value, ok := parseProbeIntOption(probe.Options, "birthday_listen_ports"); ok && value > 0 {
		plan.BirthdayListenPorts = value
	}
	if value, ok := parseProbeIntOption(probe.Options, "birthday_targets_per_port"); ok && value > 0 {
		plan.BirthdayTargetsPerPort = value
	}
	if value, ok := parseProbeIntOption(probe.Options, "nomination_delay_ms"); ok && value >= 0 {
		plan.NominationDelay = time.Duration(value) * time.Millisecond
	}
	if value, ok := parseProbeIntOption(probe.Options, "nomination_retry_ms"); ok && value > 0 {
		plan.NominationRetryInterval = time.Duration(value) * time.Millisecond
	}
	if value, ok := parseProbeBoolOption(probe.Options, "enable_birthday_attack"); !ok || !value {
		plan.AllowBirthdayFallback = false
		plan.UseBirthdayAttack = false
	}
	return plan
}

func ApplySummaryHintsToPlan(plan PunchPlan, summary P2PProbeSummary) PunchPlan {
	sharedFamilies := summaryHintInt(summary.Hints, "shared_family_count")
	strongEvidence := hasStrongProbeEvidence(summary.Self.Nat) && hasStrongProbeEvidence(summary.Peer.Nat)
	profileScore := adaptiveProfileScore(summary)
	if sharedFamilies > 1 {
		if !isHardOrUnknownNat(summary.Self.Nat) && !isHardOrUnknownNat(summary.Peer.Nat) {
			if plan.SprayRounds > 1 {
				plan.SprayRounds--
			}
			if plan.SprayBurst > 4 {
				plan.SprayBurst--
			}
		}
		delay := plan.NominationDelay
		if delay < 100*time.Millisecond {
			delay = 100 * time.Millisecond
		}
		delay += 20 * time.Millisecond
		if plan.HandshakeTimeout > 0 {
			maxDelay := plan.HandshakeTimeout / 5
			if maxDelay > 0 && delay > maxDelay {
				delay = maxDelay
			}
		}
		plan.NominationDelay = delay
	}
	if strongEvidence && !isHardOrUnknownNat(summary.Self.Nat) && !isHardOrUnknownNat(summary.Peer.Nat) {
		if plan.SprayRounds > 1 {
			plan.SprayRounds--
		}
		if plan.SprayBurst > 4 {
			plan.SprayBurst = maxInt(4, plan.SprayBurst-2)
		}
		if plan.NominationDelay > 70*time.Millisecond {
			plan.NominationDelay -= 20 * time.Millisecond
		}
		if plan.NominationRetryInterval > 220*time.Millisecond {
			plan.NominationRetryInterval = 220 * time.Millisecond
		}
	}
	switch {
	case profileScore >= 24:
		if plan.SprayRounds > 1 {
			plan.SprayRounds--
		}
		if plan.SprayBurst > 4 {
			plan.SprayBurst = maxInt(4, plan.SprayBurst-1)
		}
		if plan.NominationDelay > 70*time.Millisecond {
			plan.NominationDelay -= 15 * time.Millisecond
		}
		if plan.NominationRetryInterval > 200*time.Millisecond {
			plan.NominationRetryInterval = 200 * time.Millisecond
		}
	case profileScore <= -16 && sharedFamilies > 1:
		if plan.SprayBurst > 4 {
			plan.SprayBurst = maxInt(4, plan.SprayBurst-2)
		}
		if plan.SprayRounds > 1 {
			plan.SprayRounds--
		}
		plan.NominationDelay += 20 * time.Millisecond
	}
	return plan
}

func BuildPredictionIntervals(obs NatObservation, enablePrediction, aggressive bool) []int {
	if !enablePrediction {
		return nil
	}
	candidates := make([]int, 0, 8)
	seen := make(map[int]struct{}, 8)
	add := func(interval int) {
		if interval < 0 {
			interval = -interval
		}
		if interval <= 0 {
			return
		}
		if interval > 512 {
			return
		}
		if _, ok := seen[interval]; ok {
			return
		}
		seen[interval] = struct{}{}
		candidates = append(candidates, interval)
	}

	add(obs.ObservedInterval)
	diffs := samplePortDiffs(obs.Samples)
	add(minPositive(diffs))
	add(medianPositive(diffs))
	add(gcdPositive(diffs))
	if aggressive {
		base := append([]int(nil), candidates...)
		for _, interval := range base {
			add(interval - 1)
			add(interval + 1)
		}
	}
	add(DefaultPredictionInterval)
	if len(candidates) > 6 {
		candidates = candidates[:6]
	}
	return candidates
}

func shouldAllowBirthdayFallback(self, peer P2PPeerInfo) bool {
	if self.Nat.NATType == NATTypeSymmetric && peer.Nat.NATType == NATTypeSymmetric {
		return true
	}
	return isHardOrUnknownNat(self.Nat) && isHardOrUnknownNat(peer.Nat)
}

func tunePunchPlan(plan PunchPlan, self, peer P2PPeerInfo) PunchPlan {
	easyPair := !plan.EnablePrediction && !isHardOrUnknownNat(self.Nat) && !isHardOrUnknownNat(peer.Nat)
	hardPair := shouldAllowBirthdayFallback(self, peer)
	switch {
	case easyPair:
		plan.SprayRounds = 1
		plan.SprayBurst = 4
		plan.SprayPerPacketSleep = 5 * time.Millisecond
		plan.SprayBurstGap = 6 * time.Millisecond
		plan.SprayPhaseGap = 20 * time.Millisecond
		plan.NominationDelay = 80 * time.Millisecond
		plan.NominationRetryInterval = 180 * time.Millisecond
	case hardPair:
		plan.SprayRounds = 3
		plan.SprayBurst = 10
		plan.SprayPerPacketSleep = 5 * time.Millisecond
		plan.SprayBurstGap = 8 * time.Millisecond
		plan.SprayPhaseGap = 30 * time.Millisecond
		plan.NominationDelay = 140 * time.Millisecond
	}
	return plan
}

func isHardOrUnknownNat(obs NatObservation) bool {
	if obs.ProbePortRestricted || obs.MappingConfidenceLow || obs.NATType == NATTypeSymmetric {
		return true
	}
	if obs.NATType == NATTypeUnknown || obs.ClassificationLevel == ClassificationConfidenceLow {
		return true
	}
	if !filteringEvidenceKnown(obs) && hasProbeEvidence(obs) {
		return true
	}
	return false
}

func hasProbeEvidence(obs NatObservation) bool {
	return obs.PublicIP != "" || obs.ProbeIPCount > 0 || obs.ProbeEndpointCount > 0 || len(obs.Samples) > 0
}

func conservativeNPSOnlyEvidence(obs NatObservation) bool {
	if !hasProbeEvidence(obs) || natProbeProviderCount(obs) != 1 || !natHasProbeProvider(obs, ProbeProviderNPS) {
		return false
	}
	if obs.MappingConfidenceLow || obs.NATType == NATTypeUnknown || obs.ClassificationLevel == ClassificationConfidenceLow {
		return true
	}
	return !filteringEvidenceKnown(obs)
}

func filteringEvidenceKnown(obs NatObservation) bool {
	if obs.FilteringTested {
		return true
	}
	if obs.FilteringBehavior != "" && obs.FilteringBehavior != NATFilteringUnknown {
		return true
	}
	switch obs.NATType {
	case NATTypePortRestricted, NATTypeRestrictedCone, NATTypeCone:
		return true
	default:
		return false
	}
}

func natProbeProviderCount(obs NatObservation) int {
	if len(obs.Samples) == 0 {
		return 0
	}
	providers := make(map[string]struct{}, len(obs.Samples))
	for _, sample := range obs.Samples {
		provider := sample.Provider
		if provider == "" {
			provider = ProbeProviderNPS
		}
		providers[provider] = struct{}{}
	}
	return len(providers)
}

func natHasProbeProvider(obs NatObservation, provider string) bool {
	for _, sample := range obs.Samples {
		sampleProvider := sample.Provider
		if sampleProvider == "" {
			sampleProvider = ProbeProviderNPS
		}
		if sampleProvider == provider {
			return true
		}
	}
	return false
}

func hasStrongProbeEvidence(obs NatObservation) bool {
	if obs.MappingConfidenceLow || isHardOrUnknownNat(obs) {
		return false
	}
	if obs.ClassificationLevel == ClassificationConfidenceLow {
		return false
	}
	if !filteringEvidenceKnown(obs) {
		return false
	}
	return natProbeProviderCount(obs) > 1
}

func summaryHintInt(hints map[string]any, key string) int {
	if len(hints) == 0 {
		return 0
	}
	value, ok := hints[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int8:
		return int(typed)
	case int16:
		return int(typed)
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float32:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func parseProbeBoolOption(options map[string]string, key string) (bool, bool) {
	if len(options) == 0 {
		return false, false
	}
	raw, ok := options[key]
	if !ok {
		return false, false
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false
	}
	return value, true
}

func parseProbeIntOption(options map[string]string, key string) (int, bool) {
	if len(options) == 0 {
		return 0, false
	}
	raw, ok := options[key]
	if !ok {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return value, true
}

func BuildNatObservation(samples []ProbeSample, extraReplySeen bool) NatObservation {
	return BuildNatObservationWithEvidence(samples, extraReplySeen, true)
}

func BuildNatObservationWithEvidence(samples []ProbeSample, extraReplySeen, filteringTested bool) NatObservation {
	obs := NatObservation{
		ProbePortRestricted: filteringTested && !extraReplySeen,
		FilteringTested:     filteringTested,
		MappingBehavior:     NATMappingUnknown,
		FilteringBehavior:   NATFilteringUnknown,
		NATType:             NATTypeUnknown,
		ClassificationLevel: ClassificationConfidenceLow,
		Samples:             append([]ProbeSample(nil), samples...),
	}
	if len(samples) == 0 {
		obs.MappingConfidenceLow = true
		return obs
	}
	sorted := append([]ProbeSample(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ProbePort < sorted[j].ProbePort })
	first := sorted[0]
	obs.PublicIP = common.GetIpByAddr(first.ObservedAddr)
	ports := make([]int, 0, len(sorted))
	probeIPs := make(map[string]struct{}, len(sorted))
	probeEndpoints := make(map[string]struct{}, len(sorted))
	publicIPs := make(map[string]struct{}, len(sorted))
	uniquePorts := make(map[int]struct{}, len(sorted))
	var hasNPS bool
	for _, sample := range sorted {
		if publicIP := common.GetIpByAddr(sample.ObservedAddr); publicIP != "" {
			publicIPs[publicIP] = struct{}{}
		}
		if replyIP := probeSampleReplyIP(sample.ServerReplyAddr); replyIP != "" {
			probeIPs[replyIP] = struct{}{}
		}
		if endpointKey := probeObservationEndpointKey(sample); endpointKey != "" {
			probeEndpoints[endpointKey] = struct{}{}
		}
		if sample.Provider == ProbeProviderNPS || sample.Provider == "" {
			hasNPS = true
		}
		if p := common.GetPortByAddr(sample.ObservedAddr); p > 0 {
			ports = append(ports, p)
			uniquePorts[p] = struct{}{}
		}
	}
	obs.ObservedBasePort = minPositive(ports)
	obs.ProbeIPCount = len(probeIPs)
	if obs.ProbeIPCount == 0 {
		obs.ProbeIPCount = 1
	}
	obs.ProbeEndpointCount = len(probeEndpoints)
	if obs.ProbeEndpointCount < obs.ProbeIPCount {
		obs.ProbeEndpointCount = obs.ProbeIPCount
	}
	if obs.ProbeEndpointCount == 0 {
		obs.ProbeEndpointCount = 1
	}
	obs.ObservedInterval = computeObservedInterval(ports)
	obs.ConflictingSignals = len(publicIPs) > 1
	mappingEvidenceStrong := obs.ProbeEndpointCount > 1
	crossIPEvidence := obs.ProbeIPCount > 1
	switch {
	case mappingEvidenceStrong && len(uniquePorts) == 1:
		obs.MappingBehavior = NATMappingEndpointIndependent
	case mappingEvidenceStrong && len(uniquePorts) > 1:
		obs.MappingBehavior = NATMappingEndpointDependent
	}
	if hasNPS && filteringTested {
		if obs.ProbePortRestricted {
			obs.FilteringBehavior = NATFilteringPortRestricted
		} else {
			obs.FilteringBehavior = NATFilteringOpen
		}
	}
	switch {
	case obs.MappingBehavior == NATMappingEndpointDependent:
		obs.NATType = NATTypeSymmetric
		obs.ClassificationLevel = ClassificationConfidenceMed
	case obs.MappingBehavior == NATMappingEndpointIndependent && obs.FilteringBehavior == NATFilteringPortRestricted:
		obs.NATType = NATTypePortRestricted
		obs.ClassificationLevel = ClassificationConfidenceMed
	case obs.MappingBehavior == NATMappingEndpointIndependent && obs.FilteringBehavior == NATFilteringOpen:
		obs.NATType = NATTypeRestrictedCone
		obs.ClassificationLevel = ClassificationConfidenceMed
	}
	obs.MappingConfidenceLow = len(ports) < 3 || !mappingEvidenceStrong || obs.ConflictingSignals || (obs.ObservedInterval == 0 && obs.MappingBehavior == NATMappingUnknown)
	if !obs.ConflictingSignals {
		switch obs.NATType {
		case NATTypeSymmetric:
			if obs.ProbeEndpointCount > 1 && len(uniquePorts) > 1 {
				obs.MappingConfidenceLow = false
			}
		case NATTypePortRestricted, NATTypeRestrictedCone, NATTypeCone:
			if obs.MappingBehavior == NATMappingEndpointIndependent && obs.ProbeEndpointCount > 1 {
				obs.MappingConfidenceLow = false
			}
		}
	}
	if obs.MappingConfidenceLow {
		obs.ClassificationLevel = ClassificationConfidenceLow
		if obs.NATType == NATTypeSymmetric && mappingEvidenceStrong {
			obs.ClassificationLevel = ClassificationConfidenceMed
		}
	} else if crossIPEvidence {
		obs.ClassificationLevel = ClassificationConfidenceHigh
	}
	return obs
}

func probeObservationEndpointKey(sample ProbeSample) string {
	normalizeProbeSample(&sample)
	switch {
	case sample.ServerReplyAddr != "":
		return sample.Provider + "|" + sample.Mode + "|" + common.ValidateAddr(sample.ServerReplyAddr)
	case sample.EndpointID != "":
		return sample.Provider + "|" + sample.Mode + "|" + sample.EndpointID
	case sample.ProbePort > 0:
		return sample.Provider + "|" + sample.Mode + "|" + strconv.Itoa(sample.ProbePort)
	default:
		return ""
	}
}

func BuildPunchTargets(peer P2PPeerInfo, plan PunchPlan) []string {
	return appendPredictedPunchTargets(BuildDirectPunchTargets(peer), peer.Nat, plan.predictionIntervals(), plan.SpraySpan)
}

func BuildPreferredPunchTargets(self, peer P2PPeerInfo, plan PunchPlan) []string {
	targets := appendPredictedPunchTargets(BuildPreferredDirectPunchTargets(self, peer), peer.Nat, plan.predictionIntervals(), plan.SpraySpan)
	return appendPeerLocalFallbackTargets(targets, BuildPreferredLocalFallbackTargets(self, peer))
}

func BuildPredictedPunchTargetStages(peer P2PPeerInfo, plan PunchPlan) []PunchTargetStage {
	if peer.Nat.PublicIP == "" || peer.Nat.ObservedBasePort <= 0 || plan.SpraySpan <= 0 {
		return nil
	}
	portStages := buildPredictedPortStages(peer.Nat, plan.predictionIntervals(), plan.SpraySpan)
	if len(portStages) == 0 {
		return nil
	}
	stages := make([]PunchTargetStage, 0, len(portStages))
	for _, portStage := range portStages {
		targets := make([]string, 0, len(portStage.ports))
		for _, port := range portStage.ports {
			addr := common.ValidateAddr(net.JoinHostPort(peer.Nat.PublicIP, strconv.Itoa(port)))
			if addr == "" {
				continue
			}
			targets = append(targets, addr)
		}
		if len(targets) == 0 {
			continue
		}
		stages = append(stages, PunchTargetStage{
			Name:    portStage.name,
			Targets: targets,
		})
	}
	return stages
}

func BuildDirectPunchTargets(peer P2PPeerInfo) []string {
	targets := make([]string, 0, len(peer.Nat.Samples)+len(peer.LocalAddrs))
	seen := make(map[string]struct{})
	add := func(addr string) {
		addr = common.ValidateAddr(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		targets = append(targets, addr)
	}
	if peer.Nat.PortMapping != nil {
		add(peer.Nat.PortMapping.ExternalAddr)
	}
	for _, sample := range peer.Nat.Samples {
		add(sample.ObservedAddr)
	}
	wantIPv6 := peer.Nat.PublicIP != "" && net.ParseIP(peer.Nat.PublicIP) != nil && net.ParseIP(peer.Nat.PublicIP).To4() == nil
	for _, localAddr := range peer.LocalAddrs {
		host := common.GetIpByAddr(localAddr)
		ip := net.ParseIP(host)
		if ip != nil {
			isIPv6 := ip.To4() == nil
			if peer.Nat.PublicIP != "" && isIPv6 != wantIPv6 {
				continue
			}
		}
		add(localAddr)
	}
	return targets
}

func BuildPreferredDirectPunchTargets(self, peer P2PPeerInfo) []string {
	targets := make([]string, 0, len(peer.Nat.Samples)+len(peer.LocalAddrs)+1)
	seen := make(map[string]struct{})
	add := func(addr string) {
		addr = common.ValidateAddr(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		targets = append(targets, addr)
	}
	supportV4, supportV6 := supportedLocalFamilies(self.LocalAddrs)
	for _, localAddr := range peer.LocalAddrs {
		if !supportsPeerLocalFamily(localAddr, supportV4, supportV6) || !isLikelyDirectLocalAddr(localAddr) || !prefersPeerLocalAddr(self.LocalAddrs, localAddr) {
			continue
		}
		add(localAddr)
	}
	if peer.Nat.PortMapping != nil {
		add(peer.Nat.PortMapping.ExternalAddr)
	}
	for _, sample := range peer.Nat.Samples {
		add(sample.ObservedAddr)
	}
	return targets
}

func BuildPreferredLocalFallbackTargets(self, peer P2PPeerInfo) []string {
	targets := make([]string, 0, len(peer.LocalAddrs))
	seen := make(map[string]struct{}, len(peer.LocalAddrs))
	supportV4, supportV6 := supportedLocalFamilies(self.LocalAddrs)
	for _, localAddr := range peer.LocalAddrs {
		if !supportsPeerLocalFamily(localAddr, supportV4, supportV6) || !isLikelyDirectLocalAddr(localAddr) {
			continue
		}
		addr := common.ValidateAddr(localAddr)
		if addr == "" || prefersPeerLocalAddr(self.LocalAddrs, addr) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		targets = append(targets, addr)
	}
	return targets
}

func BuildBirthdayPunchTargets(peer P2PPeerInfo, plan PunchPlan) []string {
	targets := make([]string, 0, len(peer.Nat.Samples)+plan.BirthdayTargetsPerPort)
	seen := make(map[string]struct{})
	add := func(addr string) {
		addr = common.ValidateAddr(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		targets = append(targets, addr)
	}
	for _, sample := range peer.Nat.Samples {
		add(sample.ObservedAddr)
	}
	return appendPredictedPunchTargets(targets, peer.Nat, plan.predictionIntervals(), plan.BirthdayTargetsPerPort)
}

func supportedLocalFamilies(localAddrs []string) (bool, bool) {
	if len(localAddrs) == 0 {
		return true, true
	}
	var supportV4, supportV6 bool
	for _, addr := range localAddrs {
		ip := common.ParseIPFromAddr(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			supportV4 = true
		} else {
			supportV6 = true
		}
	}
	if !supportV4 && !supportV6 {
		return true, true
	}
	return supportV4, supportV6
}

func supportsPeerLocalFamily(addr string, supportV4, supportV6 bool) bool {
	ip := common.ParseIPFromAddr(addr)
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return supportV4
	}
	return supportV6
}

func isLikelyDirectLocalAddr(addr string) bool {
	ip := common.ParseIPFromAddr(addr)
	if ip == nil {
		return false
	}
	ip = common.NormalizeIP(ip)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	return !common.IsPublicIPStrict(ip)
}

func prefersPeerLocalAddr(selfLocalAddrs []string, peerAddr string) bool {
	peerIP := common.NormalizeIP(common.ParseIPFromAddr(peerAddr))
	if peerIP == nil || (!peerIP.IsPrivate() && !peerIP.IsLinkLocalUnicast()) {
		return false
	}
	for _, selfAddr := range selfLocalAddrs {
		selfIP := common.NormalizeIP(common.ParseIPFromAddr(selfAddr))
		if selfIP == nil {
			continue
		}
		if sameLikelyDirectSubnet(selfIP, peerIP) {
			return true
		}
	}
	return false
}

func sameLikelyDirectSubnet(a, b net.IP) bool {
	a = common.NormalizeIP(a)
	b = common.NormalizeIP(b)
	if a == nil || b == nil || (a.To4() == nil) != (b.To4() == nil) {
		return false
	}
	if av4 := a.To4(); av4 != nil {
		bv4 := b.To4()
		if bv4 == nil || !av4.IsPrivate() || !bv4.IsPrivate() {
			return false
		}
		return av4[0] == bv4[0] && av4[1] == bv4[1] && av4[2] == bv4[2]
	}
	if !(a.IsPrivate() || a.IsLinkLocalUnicast()) || !(b.IsPrivate() || b.IsLinkLocalUnicast()) {
		return false
	}
	return len(a) >= 8 && len(b) >= 8 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] &&
		a[4] == b[4] && a[5] == b[5] && a[6] == b[6] && a[7] == b[7]
}

func (p PunchPlan) predictionIntervals() []int {
	if len(p.PredictionIntervals) != 0 {
		return p.PredictionIntervals
	}
	if p.PredictionInterval > 0 {
		return []int{p.PredictionInterval}
	}
	return []int{DefaultPredictionInterval}
}

func (p PunchPlan) nominationDelay() time.Duration {
	delay := p.NominationDelay
	if delay <= 0 {
		return 0
	}
	if p.HandshakeTimeout > 0 {
		maxDelay := p.HandshakeTimeout / 6
		if maxDelay > 0 && delay > maxDelay {
			delay = maxDelay
		}
	}
	return delay
}

func (p PunchPlan) nominationRetryInterval() time.Duration {
	interval := p.NominationRetryInterval
	if interval <= 0 {
		interval = 300 * time.Millisecond
	}
	if p.HandshakeTimeout > 0 {
		maxInterval := p.HandshakeTimeout / 5
		if maxInterval > 0 && interval > maxInterval {
			interval = maxInterval
		}
	}
	if interval <= 0 {
		return 50 * time.Millisecond
	}
	return interval
}

func (p PunchPlan) renominationTimeout() time.Duration {
	timeout := p.nominationRetryInterval() * 3
	if timeout < 450*time.Millisecond {
		timeout = 450 * time.Millisecond
	}
	if p.HandshakeTimeout > 0 {
		maxTimeout := p.HandshakeTimeout / 4
		if maxTimeout > 0 && timeout > maxTimeout {
			timeout = maxTimeout
		}
	}
	return timeout
}

func (p PunchPlan) renominationCooldown() time.Duration {
	cooldown := p.nominationRetryInterval() * 2
	if cooldown < 250*time.Millisecond {
		cooldown = 250 * time.Millisecond
	}
	if p.HandshakeTimeout > 0 {
		maxCooldown := p.HandshakeTimeout / 5
		if maxCooldown > 0 && cooldown > maxCooldown {
			cooldown = maxCooldown
		}
	}
	return cooldown
}

func BuildTargetSprayPortsMulti(basePort int, intervals []int, span int) []int {
	if span <= 0 || basePort <= 0 {
		return nil
	}
	if len(intervals) == 0 {
		intervals = []int{DefaultPredictionInterval}
	}
	ports := make([]int, 0, span)
	seen := make(map[int]struct{}, span)
	appendPort := func(port int) {
		if len(ports) >= span {
			return
		}
		if port < 1 || port > 65535 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	appendPort(basePort)
	for step := 1; len(ports) < span/2; step++ {
		for _, interval := range intervals {
			if interval <= 0 {
				continue
			}
			appendPort(basePort + step*interval)
			appendPort(basePort - step*interval)
			if len(ports) >= span/2 {
				break
			}
		}
	}
	for delta := 1; len(ports) < span; delta++ {
		appendPort(basePort - delta)
		appendPort(basePort + delta)
	}
	return ports
}

func BuildPredictedPorts(obs NatObservation, intervals []int, span int) []int {
	stages := buildPredictedPortStages(obs, intervals, span)
	if len(stages) == 0 {
		return nil
	}
	ports := make([]int, 0, span)
	for _, stage := range stages {
		ports = append(ports, stage.ports...)
	}
	return ports
}

type predictedPortStage struct {
	name  string
	ports []int
}

func buildPredictedPortStages(obs NatObservation, intervals []int, span int) []predictedPortStage {
	if span <= 0 || obs.PublicIP == "" || obs.ObservedBasePort <= 0 {
		return nil
	}
	candidates := []predictedPortStage{
		{name: "target_likely_next", ports: buildLikelyNextPredictionPorts(obs, intervals, minInt(span, 4))},
		{name: "target_history_exact", ports: buildHistoricalPredictionPorts(obs, span)},
		{name: "target_history_neighbor", ports: buildHistoricalPredictionNeighborPorts(obs, intervals, span)},
		{name: "target_interval_sweep", ports: BuildTargetSprayPortsMulti(obs.ObservedBasePort, intervals, span)},
	}
	remaining := span
	seen := make(map[int]struct{}, span)
	out := make([]predictedPortStage, 0, len(candidates))
	for _, candidate := range candidates {
		if remaining <= 0 {
			break
		}
		filtered := make([]int, 0, len(candidate.ports))
		for _, port := range candidate.ports {
			if remaining <= 0 {
				break
			}
			if port < 1 || port > 65535 {
				continue
			}
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			filtered = append(filtered, port)
			remaining--
		}
		if len(filtered) == 0 {
			continue
		}
		candidate.ports = filtered
		out = append(out, candidate)
	}
	return out
}

func buildLikelyNextPredictionPorts(obs NatObservation, intervals []int, span int) []int {
	if span <= 0 {
		return nil
	}
	observed := observedPorts(obs)
	if len(observed) < 2 {
		return nil
	}
	anchor := obs.ObservedBasePort
	if len(observed) > 0 {
		anchor = observed[len(observed)-1]
	}
	steps := likelyNextPredictionSteps(obs, intervals)
	out := make([]int, 0, span)
	seen := make(map[int]struct{}, span)
	add := func(port int) {
		if len(out) >= span {
			return
		}
		if port < 1 || port > 65535 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	for _, step := range steps {
		add(anchor + step)
		if step > 1 {
			add(anchor + 1)
		}
		if len(observed) >= 2 {
			add(anchor + 2*step)
		}
	}
	return out
}

func buildHistoricalPredictionPorts(obs NatObservation, span int) []int {
	if span <= 0 || obs.ObservedBasePort <= 0 {
		return nil
	}
	offsets := predictionHistoryOffsets(obs)
	if len(offsets) == 0 {
		return nil
	}
	out := make([]int, 0, len(offsets))
	seen := make(map[int]struct{}, len(offsets))
	for _, offset := range offsets {
		port := obs.ObservedBasePort + offset
		if port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
		if len(out) >= span {
			break
		}
	}
	return out
}

func buildHistoricalPredictionNeighborPorts(obs NatObservation, intervals []int, span int) []int {
	if span <= 0 || obs.ObservedBasePort <= 0 {
		return nil
	}
	offsets := predictionHistoryOffsets(obs)
	if len(offsets) == 0 {
		return nil
	}
	steps := predictionNeighborSteps(intervals)
	anchors := offsets
	if len(anchors) > 3 {
		anchors = anchors[:3]
	}
	out := make([]int, 0, span)
	seen := make(map[int]struct{}, span)
	add := func(port int) {
		if len(out) >= span {
			return
		}
		if port < 1 || port > 65535 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	for _, offset := range anchors {
		base := obs.ObservedBasePort + offset
		for _, step := range steps {
			add(base - step)
			add(base + step)
			if len(out) >= span {
				return out
			}
		}
	}
	return out
}

func observedPorts(obs NatObservation) []int {
	if len(obs.Samples) == 0 {
		if obs.ObservedBasePort > 0 {
			return []int{obs.ObservedBasePort}
		}
		return nil
	}
	out := make([]int, 0, len(obs.Samples))
	seen := make(map[int]struct{}, len(obs.Samples))
	for _, sample := range obs.Samples {
		port := common.GetPortByAddr(sample.ObservedAddr)
		if port <= 0 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func likelyNextPredictionSteps(obs NatObservation, intervals []int) []int {
	steps := make([]int, 0, 4)
	seen := make(map[int]struct{}, 4)
	add := func(step int) {
		if step <= 0 || step > 64 {
			return
		}
		if _, ok := seen[step]; ok {
			return
		}
		seen[step] = struct{}{}
		steps = append(steps, step)
	}
	add(obs.ObservedInterval)
	diffs := samplePortDiffs(obs.Samples)
	add(dominantPositive(diffs))
	add(medianPositive(diffs))
	for _, interval := range intervals {
		add(interval)
		if len(steps) >= 4 {
			break
		}
	}
	add(1)
	return steps
}

func predictionNeighborSteps(intervals []int) []int {
	steps := make([]int, 0, 4)
	seen := make(map[int]struct{}, 4)
	add := func(step int) {
		if step <= 0 || step > 64 {
			return
		}
		if _, ok := seen[step]; ok {
			return
		}
		seen[step] = struct{}{}
		steps = append(steps, step)
	}
	add(1)
	for _, interval := range intervals {
		add(interval)
		if len(steps) >= 4 {
			break
		}
	}
	return steps
}

func appendPredictedPunchTargets(targets []string, obs NatObservation, intervals []int, span int) []string {
	if len(targets) == 0 {
		targets = make([]string, 0, span)
	}
	seen := make(map[string]struct{}, len(targets)+span)
	for _, target := range targets {
		target = common.ValidateAddr(target)
		if target == "" {
			continue
		}
		seen[target] = struct{}{}
	}
	add := func(addr string) {
		addr = common.ValidateAddr(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		targets = append(targets, addr)
	}
	for _, port := range BuildPredictedPorts(obs, intervals, span) {
		add(net.JoinHostPort(obs.PublicIP, strconv.Itoa(port)))
	}
	return targets
}

func appendPeerLocalFallbackTargets(targets, fallbacks []string) []string {
	if len(fallbacks) == 0 {
		return targets
	}
	seen := make(map[string]struct{}, len(targets)+len(fallbacks))
	for _, target := range targets {
		target = common.ValidateAddr(target)
		if target == "" {
			continue
		}
		seen[target] = struct{}{}
	}
	for _, fallback := range fallbacks {
		fallback = common.ValidateAddr(fallback)
		if fallback == "" {
			continue
		}
		if _, ok := seen[fallback]; ok {
			continue
		}
		seen[fallback] = struct{}{}
		targets = append(targets, fallback)
	}
	return targets
}

func BuildTargetSprayPorts(basePort, interval, span int) []int {
	if span <= 0 {
		return nil
	}
	if basePort <= 0 {
		return nil
	}
	if interval <= 0 {
		interval = DefaultPredictionInterval
	}
	ports := make([]int, 0, span)
	seen := make(map[int]struct{}, span)
	appendPort := func(port int) {
		if len(ports) >= span {
			return
		}
		if port < 1 || port > 65535 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	appendPort(basePort)
	for delta := 1; len(ports) < span/2; delta++ {
		appendPort(basePort + delta*interval)
		appendPort(basePort - delta*interval)
	}
	for delta := 1; len(ports) < span; delta++ {
		appendPort(basePort - delta)
		appendPort(basePort + delta)
	}
	return ports
}

func computeObservedInterval(ports []int) int {
	if len(ports) < 2 {
		return 0
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	diffs := make([]int, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		diff := sorted[i] - sorted[i-1]
		if diff < 0 {
			diff = -diff
		}
		if diff > 0 {
			diffs = append(diffs, diff)
		}
	}
	if len(diffs) == 0 {
		return 0
	}
	if dominant := dominantPositive(diffs); dominant > 0 {
		return dominant
	}
	if gcd := gcdPositive(diffs); gcd > 1 {
		return gcd
	}
	return minPositive(diffs)
}

func samplePortDiffs(samples []ProbeSample) []int {
	if len(samples) < 2 {
		return nil
	}
	ports := make([]int, 0, len(samples))
	for _, sample := range samples {
		if port := common.GetPortByAddr(sample.ObservedAddr); port > 0 {
			ports = append(ports, port)
		}
	}
	if len(ports) < 2 {
		return nil
	}
	sort.Ints(ports)
	diffs := make([]int, 0, len(ports)-1)
	for i := 1; i < len(ports); i++ {
		diff := ports[i] - ports[i-1]
		if diff < 0 {
			diff = -diff
		}
		if diff > 0 {
			diffs = append(diffs, diff)
		}
	}
	return diffs
}

func minPositive(values []int) int {
	minValue := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if minValue == 0 || value < minValue {
			minValue = value
		}
	}
	return minValue
}

func medianPositive(values []int) int {
	filtered := make([]int, 0, len(values))
	for _, value := range values {
		if value > 0 {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == 0 {
		return 0
	}
	sort.Ints(filtered)
	return filtered[len(filtered)/2]
}

func gcdPositive(values []int) int {
	gcd := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if gcd == 0 {
			gcd = value
			continue
		}
		gcd = gcdPair(gcd, value)
	}
	return gcd
}

func dominantPositive(values []int) int {
	counts := make(map[int]int, len(values))
	bestValue := 0
	bestCount := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		counts[value]++
		if counts[value] > bestCount || (counts[value] == bestCount && (bestValue == 0 || value < bestValue)) {
			bestValue = value
			bestCount = counts[value]
		}
	}
	return bestValue
}

func gcdPair(a, b int) int {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
