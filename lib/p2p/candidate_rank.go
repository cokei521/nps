package p2p

import (
	"fmt"
	"strings"

	"github.com/djylb/nps/lib/common"
)

const (
	candidateTierResponsive = 350000
	candidateTierDirect     = 300000
	candidateTierTargetFast = 240000
	candidateTierTargetHist = 230000
	candidateTierTargetNear = 220000
	candidateTierTarget     = 200000
	candidateTierLocal      = 150000
	candidateTierBirthday   = 100000
	candidateTierFallback   = 50000
)

type CandidatePriority struct {
	Score  int
	Reason string
}

type CandidateRanker struct {
	priorities   map[string]CandidatePriority
	direct       []string
	target       []string
	targetPhases []PunchTargetStage
	birthday     []string
	peerPublic   string
	peerPort     int
	selfLocal    []string
}

func NewCandidateRanker(self, peer P2PPeerInfo, plan PunchPlan) *CandidateRanker {
	r := &CandidateRanker{
		priorities: make(map[string]CandidatePriority),
		peerPublic: peer.Nat.PublicIP,
		peerPort:   peer.Nat.ObservedBasePort,
		selfLocal:  append([]string(nil), self.LocalAddrs...),
	}
	r.direct = r.addOrdered("direct", BuildPreferredDirectPunchTargets(self, peer), candidateTierDirect)
	if plan.UseTargetSpray {
		r.target = append([]string(nil), r.direct...)
		r.targetPhases = BuildPredictedPunchTargetStages(peer, plan)
		if localFallback := BuildPreferredLocalFallbackTargets(self, peer); len(localFallback) > 0 {
			r.targetPhases = append(r.targetPhases, PunchTargetStage{
				Name:    "target_local_fallback",
				Targets: localFallback,
			})
		}
		for _, phase := range r.targetPhases {
			r.target = appendOrderedUnique(r.target, r.addOrdered(phase.Name, phase.Targets, targetStagePriorityBase(phase.Name)))
		}
		if len(r.target) == 0 {
			r.target = r.addOrdered("target", BuildPreferredPunchTargets(self, peer, plan), candidateTierTarget)
		}
	} else {
		r.target = append([]string(nil), r.direct...)
		r.addOrdered("target", r.target, candidateTierTarget)
	}
	if plan.UseBirthdayAttack || plan.AllowBirthdayFallback {
		r.birthday = r.addOrdered("birthday", BuildBirthdayPunchTargets(peer, plan), candidateTierBirthday)
	}
	if observed := firstObservedAddr(peer); observed != "" {
		r.addPriority(observed, CandidatePriority{
			Score:  candidateTierFallback,
			Reason: "observed_fallback",
		})
	}
	return r
}

func (r *CandidateRanker) DirectTargets() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.direct...)
}

func (r *CandidateRanker) PrimaryTargets(useTargetSpray bool) []string {
	if r == nil {
		return nil
	}
	if useTargetSpray {
		return append([]string(nil), r.target...)
	}
	return append([]string(nil), r.direct...)
}

func (r *CandidateRanker) TargetOnlyTargets() []string {
	if r == nil {
		return nil
	}
	if len(r.target) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(r.direct))
	for _, addr := range r.direct {
		seen[addr] = struct{}{}
	}
	out := make([]string, 0, len(r.target))
	for _, addr := range r.target {
		if _, ok := seen[addr]; ok {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func (r *CandidateRanker) BirthdayTargets() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.birthday...)
}

func (r *CandidateRanker) TargetStages() []PunchTargetStage {
	if r == nil || len(r.targetPhases) == 0 {
		return nil
	}
	return cloneTargetStages(r.targetPhases)
}

func (r *CandidateRanker) Priority(_ string, remoteAddr string) CandidatePriority {
	if r == nil {
		return CandidatePriority{Score: 1, Reason: "unplanned"}
	}
	remoteAddr = common.ValidateAddr(remoteAddr)
	if remoteAddr == "" {
		return CandidatePriority{}
	}
	if priority, ok := r.priorities[remoteAddr]; ok {
		return priority
	}
	if r.peerPublic != "" && common.GetIpByAddr(remoteAddr) == r.peerPublic {
		delta := absInt(common.GetPortByAddr(remoteAddr) - r.peerPort)
		if r.peerPort > 0 {
			return CandidatePriority{
				Score:  candidateTierFallback - minInt(delta, 4096),
				Reason: fmt.Sprintf("public_fallback(delta=%d)", delta),
			}
		}
		return CandidatePriority{
			Score:  candidateTierFallback - 8192,
			Reason: "public_fallback",
		}
	}
	if isLikelyDirectLocalAddr(remoteAddr) {
		if prefersPeerLocalAddr(r.selfLocal, remoteAddr) {
			return CandidatePriority{
				Score:  candidateTierFallback + 16384,
				Reason: "peer_local_fallback_same_subnet",
			}
		}
		return CandidatePriority{
			Score:  candidateTierFallback - 16384,
			Reason: "peer_local_fallback_foreign",
		}
	}
	return CandidatePriority{
		Score:  1,
		Reason: "unplanned",
	}
}

func (r *CandidateRanker) ResponsivePriority(remoteAddr string) CandidatePriority {
	if r == nil {
		return CandidatePriority{Score: candidateTierResponsive, Reason: "responsive_unplanned"}
	}
	remoteAddr = common.ValidateAddr(remoteAddr)
	if remoteAddr == "" {
		return CandidatePriority{}
	}
	if isLikelyDirectLocalAddr(remoteAddr) {
		if prefersPeerLocalAddr(r.selfLocal, remoteAddr) {
			return CandidatePriority{
				Score:  candidateTierResponsive + 16384,
				Reason: "responsive_same_subnet",
			}
		}
		return CandidatePriority{
			Score:  candidateTierResponsive,
			Reason: "responsive_peer_local",
		}
	}
	if r.peerPublic != "" && common.GetIpByAddr(remoteAddr) == r.peerPublic {
		delta := absInt(common.GetPortByAddr(remoteAddr) - r.peerPort)
		return CandidatePriority{
			Score:  candidateTierResponsive - minInt(delta, 8192),
			Reason: fmt.Sprintf("responsive_public(delta=%d)", delta),
		}
	}
	if existing, ok := r.priorities[remoteAddr]; ok {
		score := existing.Score + 64
		if score < candidateTierResponsive-8192 {
			score = candidateTierResponsive - 8192
		}
		return CandidatePriority{
			Score:  score,
			Reason: "validated_" + trimPriorityReason(existing.Reason),
		}
	}
	return CandidatePriority{
		Score:  candidateTierResponsive - 12000,
		Reason: "responsive_unplanned",
	}
}

func (r *CandidateRanker) addOrdered(tier string, addrs []string, base int) []string {
	ordered := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for i, addr := range addrs {
		addr = common.ValidateAddr(addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		ordered = append(ordered, addr)
		r.addPriority(addr, CandidatePriority{
			Score:  base - i,
			Reason: fmt.Sprintf("%s[%d]", tier, i),
		})
	}
	return ordered
}

func (r *CandidateRanker) addPriority(addr string, priority CandidatePriority) {
	if r == nil {
		return
	}
	addr = common.ValidateAddr(addr)
	if addr == "" {
		return
	}
	if existing, ok := r.priorities[addr]; ok && existing.Score >= priority.Score {
		return
	}
	r.priorities[addr] = priority
}

func trimPriorityReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "candidate"
	}
	return reason
}

func targetStagePriorityBase(name string) int {
	switch name {
	case "target_likely_next":
		return candidateTierTargetFast
	case "target_history_exact":
		return candidateTierTargetHist
	case "target_history_neighbor":
		return candidateTierTargetNear
	case "target_local_fallback":
		return candidateTierLocal
	default:
		return candidateTierTarget
	}
}

func appendOrderedUnique(base []string, addrs []string) []string {
	if len(addrs) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(addrs))
	for _, addr := range base {
		seen[addr] = struct{}{}
	}
	for _, addr := range addrs {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		base = append(base, addr)
	}
	return base
}

func cloneTargetStages(stages []PunchTargetStage) []PunchTargetStage {
	out := make([]PunchTargetStage, 0, len(stages))
	for _, stage := range stages {
		out = append(out, PunchTargetStage{
			Name:    stage.Name,
			Targets: append([]string(nil), stage.Targets...),
		})
	}
	return out
}
