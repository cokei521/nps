package p2p

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
)

func (s *runtimeSession) startSpray(ctx context.Context) {
	directTargets := filterPunchTargetsForLocalAddr(s.localConn.LocalAddr(), s.directSprayTargets())
	targetPhases := filterTargetStagesForLocalAddr(s.localConn.LocalAddr(), s.targetSprayStages())
	targetTargets := flattenTargetStages(targetPhases)
	primaryTargets := directTargets
	if s.plan.UseTargetSpray {
		primaryTargets = append(append([]string(nil), directTargets...), targetTargets...)
	}
	if len(primaryTargets) == 0 {
		return
	}
	mode := "direct"
	if s.plan.UseTargetSpray && len(targetTargets) > 0 {
		mode = "staged"
	}
	_ = s.sendProgress("spray_started", "ok", mode, addrString(s.localConn.LocalAddr()), "", map[string]string{
		"target_count":        strconv.Itoa(len(primaryTargets)),
		"direct_target_count": strconv.Itoa(len(directTargets)),
		"target_only_count":   strconv.Itoa(len(targetTargets)),
		"base_port":           strconv.Itoa(s.summary.Peer.Nat.ObservedBasePort),
		"rounds":              strconv.Itoa(s.plan.SprayRounds),
		"burst":               strconv.Itoa(s.plan.SprayBurst),
		"intervals":           fmt.Sprint(s.plan.predictionIntervals()),
	})
	if len(directTargets) > 0 {
		s.startSprayPhase(ctx, "direct", directTargets, directPhaseRounds(s.plan), directPhaseBurst(s.plan))
	}
	if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
		return
	}
	if s.plan.UseTargetSpray {
		for _, phase := range targetPhases {
			rounds, burst := targetPhaseBudget(s.plan, phase.Name)
			s.startSprayPhase(ctx, phase.Name, phase.Targets, rounds, burst)
			if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
				return
			}
		}
	}
	if s.plan.UseBirthdayAttack || s.plan.AllowBirthdayFallback {
		if !s.plan.UseBirthdayAttack {
			s.enableBirthdayFallback()
			_ = s.sendProgress("birthday_fallback_enabled", "ok", "", addrString(s.localConn.LocalAddr()), "", nil)
			logs.Info("[P2P] spray fallback=target_to_birthday role=%s", s.start.Role)
		}
		s.runBirthdaySpray(ctx)
		return
	}
	s.runPeriodicSpray(ctx, s.snapshotSockets(), primaryTargets)
}

func (s *runtimeSession) runBirthdaySpray(ctx context.Context) {
	targets := s.birthdaySprayTargets()
	targets = filterPunchTargetsForLocalAddr(s.localConn.LocalAddr(), targets)
	if len(targets) == 0 {
		return
	}
	baseBind := buildAdditionalBindAddr(s.localConn.LocalAddr())
	if baseBind == "" {
		s.runPeriodicSpray(ctx, s.snapshotSockets(), targets)
		return
	}
	logs.Info("[P2P] spray mode=birthday listenPorts=%d targetsPerPort=%d",
		s.plan.BirthdayListenPorts, s.plan.BirthdayTargetsPerPort)
	for round := 0; round < s.plan.SprayRounds; round++ {
		desired := 1 << round
		if desired < 1 {
			desired = 1
		}
		if desired > s.plan.BirthdayListenPorts {
			desired = s.plan.BirthdayListenPorts
		}
		activeSockets := s.ensureBirthdaySockets(ctx, baseBind, desired)
		_ = s.sendProgress("birthday_phase", "ok", fmt.Sprintf("phase=%d", round+1), addrString(s.localConn.LocalAddr()), "", map[string]string{
			"listen_ports":     strconv.Itoa(len(activeSockets)),
			"targets_per_port": strconv.Itoa(len(targets)),
		})
		s.runSprayMatrixOnce(ctx, activeSockets, targets)
		if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
			return
		}
		if round < s.plan.SprayRounds-1 && !sleepContext(ctx, s.ensurePacer().sprayPhaseGap(round, s.plan.SprayPhaseGap)) {
			return
		}
	}
	s.runPeriodicSpray(ctx, s.ensureBirthdaySockets(ctx, baseBind, s.plan.BirthdayListenPorts), targets)
}

func (s *runtimeSession) runSprayRounds(ctx context.Context, sendConn net.PacketConn, targets []string) {
	s.runSprayRoundsWithBudget(ctx, sendConn, targets, s.plan.SprayRounds, s.plan.SprayBurst)
}

func (s *runtimeSession) runSprayRoundsWithBudget(ctx context.Context, sendConn net.PacketConn, targets []string, rounds, burst int) {
	if rounds <= 0 || burst <= 0 {
		return
	}
	for round := 0; round < rounds; round++ {
		s.runSprayPassWithBurst(ctx, sendConn, targets, burst)
		if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
			return
		}
		if round < rounds-1 && !sleepContext(ctx, s.ensurePacer().sprayPhaseGap(round, s.plan.SprayPhaseGap)) {
			return
		}
	}
}

func (s *runtimeSession) runSprayMatrixOnce(ctx context.Context, sockets []net.PacketConn, targets []string) {
	for _, socket := range sockets {
		if socket == nil {
			continue
		}
		s.runSprayPass(ctx, socket, targets)
		if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
			return
		}
	}
}

func (s *runtimeSession) runPeriodicSpray(ctx context.Context, sockets []net.PacketConn, targets []string) {
	for attempt := 0; ; attempt++ {
		if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
			return
		}
		delay := s.ensurePacer().periodicRetryDelay(attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
				return
			}
			_ = s.sendProgress("spray_retry", "ok", fmt.Sprintf("attempt=%d", attempt+1), addrString(s.localConn.LocalAddr()), s.cm.CandidateRemote(), map[string]string{
				"delay_ms":     strconv.FormatInt(delay.Milliseconds(), 10),
				"socket_count": strconv.Itoa(len(sockets)),
				"target_count": strconv.Itoa(len(targets)),
			})
			s.runSprayMatrixOnce(ctx, sockets, targets)
		}
	}
}

func (s *runtimeSession) runSprayPass(ctx context.Context, sendConn net.PacketConn, targets []string) {
	s.runSprayPassWithBurst(ctx, sendConn, targets, s.plan.SprayBurst)
}

func (s *runtimeSession) runSprayPassWithBurst(ctx context.Context, sendConn net.PacketConn, targets []string, burstCount int) {
	pacer := s.ensurePacer()
	resolvedTargets := s.resolvePunchTargets(sendConn.LocalAddr(), targets)
	for _, target := range resolvedTargets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
			return
		}
		for burst := 0; burst < burstCount; burst++ {
			if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
				return
			}
			_ = s.writeUDPToConn(sendConn, packetTypePunch, target.addr)
			if !sleepContext(ctx, pacer.sprayPacketGap(target.index, burst, s.plan.SprayPerPacketSleep)) {
				return
			}
		}
		if target.index < len(targets)-1 && !sleepContext(ctx, pacer.sprayBurstGap(target.index, s.plan.SprayBurstGap)) {
			return
		}
	}
}

func (s *runtimeSession) startSprayPhase(ctx context.Context, phase string, targets []string, rounds, burst int) {
	if len(targets) == 0 || rounds <= 0 || burst <= 0 {
		return
	}
	_ = s.sendProgress("spray_phase", "ok", phase, addrString(s.localConn.LocalAddr()), "", map[string]string{
		"target_count": strconv.Itoa(len(targets)),
		"rounds":       strconv.Itoa(rounds),
		"burst":        strconv.Itoa(burst),
	})
	logs.Info("[P2P] spray phase=%s basePort=%d intervals=%v rounds=%d burst=%d targets=%d",
		phase, s.summary.Peer.Nat.ObservedBasePort, s.plan.predictionIntervals(), rounds, burst, len(targets))
	s.runSprayRoundsWithBudget(ctx, s.localConn, targets, rounds, burst)
}

func directPhaseRounds(plan PunchPlan) int {
	if plan.SprayRounds <= 1 {
		return 1
	}
	return 1
}

func directPhaseBurst(plan PunchPlan) int {
	if plan.SprayBurst <= 0 {
		return 0
	}
	if plan.SprayBurst < 4 {
		return plan.SprayBurst
	}
	return 4
}

func buildAdditionalBindAddr(localAddr net.Addr) string {
	if localAddr == nil {
		return ""
	}
	host := common.GetIpByAddr(localAddr.String())
	if host == "" {
		return ""
	}
	return common.BuildAddress(host, "0")
}

func (s *runtimeSession) ensureBirthdaySockets(ctx context.Context, bindAddr string, desired int) []net.PacketConn {
	if desired <= 0 {
		return nil
	}
	sockets := s.snapshotSockets()
	for len(sockets) < desired {
		birthdayConn, err := conn.NewUdpConnByAddr(bindAddr)
		if err != nil {
			break
		}
		s.addSocket(birthdayConn)
		s.startReadLoop(ctx, birthdayConn)
		sockets = append(sockets, birthdayConn)
	}
	if len(sockets) > desired {
		sockets = sockets[:desired]
	}
	return sockets
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func filterPunchTargetsForLocalAddr(localAddr net.Addr, targets []string) []string {
	family := detectAddrFamily(localAddr)
	if len(targets) == 0 {
		return nil
	}
	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		target = common.ValidateAddr(target)
		if target == "" || !family.matchesAddr(target) {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func (s *runtimeSession) directSprayTargets() []string {
	if s == nil {
		return nil
	}
	ranker := s.ensureRanker()
	return ranker.DirectTargets()
}

func (s *runtimeSession) targetSprayStages() []PunchTargetStage {
	if s == nil {
		return nil
	}
	ranker := s.ensureRanker()
	return ranker.TargetStages()
}

func (s *runtimeSession) birthdaySprayTargets() []string {
	if s == nil {
		return nil
	}
	ranker := s.ensureRanker()
	return ranker.BirthdayTargets()
}

func filterTargetStagesForLocalAddr(localAddr net.Addr, stages []PunchTargetStage) []PunchTargetStage {
	if len(stages) == 0 {
		return nil
	}
	filtered := make([]PunchTargetStage, 0, len(stages))
	for _, stage := range stages {
		targets := filterPunchTargetsForLocalAddr(localAddr, stage.Targets)
		if len(targets) == 0 {
			continue
		}
		filtered = append(filtered, PunchTargetStage{
			Name:    stage.Name,
			Targets: targets,
		})
	}
	return filtered
}

func flattenTargetStages(stages []PunchTargetStage) []string {
	if len(stages) == 0 {
		return nil
	}
	out := make([]string, 0)
	for _, stage := range stages {
		out = appendOrderedUnique(out, stage.Targets)
	}
	return out
}

func targetPhaseBudget(plan PunchPlan, phase string) (int, int) {
	switch phase {
	case "target_likely_next":
		return 1, minInt(plan.SprayBurst, 4)
	case "target_history_exact":
		return 1, minInt(plan.SprayBurst, 5)
	case "target_history_neighbor":
		return maxInt(1, plan.SprayRounds-1), minInt(plan.SprayBurst, 6)
	case "target_local_fallback":
		return 1, minInt(plan.SprayBurst, 2)
	default:
		return plan.SprayRounds, plan.SprayBurst
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
