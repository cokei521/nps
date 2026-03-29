package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
)

const (
	controlBurstGap   = 10 * time.Millisecond
	readyBurstGap     = 15 * time.Millisecond
	successBurstCount = 2
	readyBurstCount   = 4
)

func (s *runtimeSession) readLoopOnConn(ctx context.Context, readConn net.PacketConn) {
	s.addSocket(readConn)
	buf := common.BufPoolUdp.Get()
	defer common.BufPoolUdp.Put(buf)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = readConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := readConn.ReadFrom(buf)
		_ = readConn.SetReadDeadline(time.Time{})
		if err != nil {
			if conn.IsTimeout(err) || isIgnorableUDPIcmpError(err) {
				continue
			}
			return
		}
		packet, err := DecodeUDPPacket(buf[:n], s.start.Token)
		if err != nil {
			if errors.Is(err, ErrP2PTokenMismatch) {
				s.recordTokenMismatch()
			}
			continue
		}
		if packet.SessionID != s.start.SessionID || packet.Token != s.start.Token {
			s.recordTokenMismatch()
			continue
		}
		if routeID := p2pStartWireSpec(s.start).RouteID; routeID != "" && !SameWireRoute(packet.WireID, routeID) {
			s.recordTokenMismatch()
			continue
		}
		if !s.acceptReplay(packet) {
			continue
		}
		s.recordTokenVerified()
		remoteAddr := addr.String()
		localAddr := readConn.LocalAddr().String()
		switch packet.Type {
		case packetTypeProbe, packetTypePunch:
			s.cm.Observe(localAddr, remoteAddr)
			s.updateCandidateRemote(remoteAddr)
			s.sendSuccessBurst(ctx, readConn, addr)
		case packetTypeSucc:
			logs.Info("[P2P] SUCCESS received local=%s remote=%s", localAddr, remoteAddr)
			s.cm.Observe(localAddr, remoteAddr)
			priority := s.successCandidatePriority(localAddr, remoteAddr)
			pair := s.cm.MarkSucceededWithPriority(localAddr, remoteAddr, priority)
			s.updateCandidateRemote(remoteAddr)
			if pair != nil {
				logs.Info("[P2P] candidate hit local=%s remote=%s score=%d reason=%s successes=%d", localAddr, remoteAddr, pair.Score, pair.ScoreReason, pair.SuccessCount)
			} else {
				logs.Info("[P2P] candidate hit local=%s remote=%s", localAddr, remoteAddr)
			}
			_ = s.sendProgress("success_received", "ok", remoteAddr, localAddr, remoteAddr, candidateMeta(pair))
			if s.start.Role == common.WORK_P2P_VISITOR {
				s.scheduleBestNomination(ctx)
			} else {
				s.sendSuccessBurst(ctx, readConn, addr)
			}
		case packetTypeEnd:
			logs.Info("[P2P] END received local=%s remote=%s", localAddr, remoteAddr)
			s.cm.Observe(localAddr, remoteAddr)
			if s.start.Role == common.WORK_P2P_PROVIDER {
				epoch := effectiveNominationEpoch(packet)
				if epoch == 0 {
					continue
				}
				if pair, adopted := s.adoptInboundProposal(localAddr, remoteAddr, epoch); adopted || (pair != nil && pair.Nominated) {
					logs.Info("[P2P] candidate proposed local=%s remote=%s epoch=%d", localAddr, remoteAddr, epoch)
					s.sendAcceptBurst(ctx, readConn, addr, epoch)
					_ = s.sendProgress("candidate_proposed", "ok", remoteAddr, localAddr, remoteAddr, map[string]string{
						"nomination_epoch": fmt.Sprintf("%d", epoch),
					})
					s.startAcceptLoop(ctx, readConn, addr, epoch)
				}
			}
		case packetTypeAccept:
			logs.Info("[P2P] ACCEPT received local=%s remote=%s", localAddr, remoteAddr)
			s.cm.Observe(localAddr, remoteAddr)
			if s.start.Role == common.WORK_P2P_VISITOR {
				epoch := effectiveNominationEpoch(packet)
				if !s.matchesOutboundNomination(localAddr, remoteAddr, epoch) {
					continue
				}
				if confirmed := s.cm.Confirm(localAddr, remoteAddr); confirmed != nil {
					logs.Info("[P2P] candidate confirmed local=%s remote=%s", localAddr, remoteAddr)
					s.updateConfirmedRemote(remoteAddr)
					s.clearOutboundNomination(localAddr, remoteAddr, epoch)
					s.sendControlBurst(ctx, readConn, packetTypeReady, addr, readyBurstCount, readyBurstGap, epoch)
					_ = s.sendProgress("accept_received", "ok", remoteAddr, localAddr, remoteAddr, map[string]string{
						"nomination_epoch": fmt.Sprintf("%d", epoch),
					})
					s.signalConfirmed(readConn, localAddr, remoteAddr)
				}
			}
		case packetTypeReady:
			logs.Info("[P2P] READY received local=%s remote=%s", localAddr, remoteAddr)
			s.cm.Observe(localAddr, remoteAddr)
			if s.start.Role == common.WORK_P2P_PROVIDER {
				epoch := effectiveNominationEpoch(packet)
				if !s.matchesInboundProposal(localAddr, remoteAddr, epoch) {
					continue
				}
				if confirmed := s.cm.Confirm(localAddr, remoteAddr); confirmed != nil {
					logs.Info("[P2P] candidate confirmed local=%s remote=%s epoch=%d", localAddr, remoteAddr, epoch)
					s.updateConfirmedRemote(remoteAddr)
					_ = s.sendProgress("ready_received", "ok", remoteAddr, localAddr, remoteAddr, map[string]string{
						"nomination_epoch": fmt.Sprintf("%d", epoch),
					})
					s.signalConfirmed(readConn, localAddr, remoteAddr)
				}
			}
		}
	}
}

func (s *runtimeSession) writeUDPToConn(writeConn net.PacketConn, packetType string, addr net.Addr) error {
	return s.writeUDPToConnWithEpoch(writeConn, packetType, addr, 0)
}

func (s *runtimeSession) writeUDPToConnWithEpoch(writeConn net.PacketConn, packetType string, addr net.Addr, epoch uint32) error {
	packet := newUDPPacketWithWire(s.start.SessionID, s.start.Token, s.start.Role, packetType, p2pStartWireSpec(s.start))
	packet.NominationEpoch = epoch
	raw, err := EncodeUDPPacket(packet)
	if err != nil {
		return err
	}
	_, err = writeConn.WriteTo(raw, addr)
	return err
}

func (s *runtimeSession) updateCandidateRemote(remote string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endpoints.ConfirmedRemote != "" && s.endpoints.ConfirmedRemote != remote {
		return
	}
	if s.endpoints.CandidateRemote != "" && s.endpoints.CandidateRemote != remote {
		logs.Info("[P2P] remote corrected old=%s new=%s", s.endpoints.CandidateRemote, remote)
	}
	s.endpoints.CandidateRemote = remote
}

func (s *runtimeSession) updateConfirmedRemote(remote string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endpoints.ConfirmedRemote != "" && s.endpoints.ConfirmedRemote != remote {
		return
	}
	s.endpoints.CandidateRemote = remote
	s.endpoints.ConfirmedRemote = remote
}

func (s *runtimeSession) signalConfirmed(readConn net.PacketConn, localAddr, remote string) {
	select {
	case s.confirmed <- confirmedPair{owner: s, conn: readConn, localAddr: localAddr, remoteAddr: remote}:
	default:
	}
}

func trySendProgress(c *conn.Conn, sessionID, role, stage, detail string) error {
	return trySendProgressWithStatus(c, sessionID, role, stage, "ok", detail, "", "", nil, nil)
}

func trySendProgressWithStatus(c *conn.Conn, sessionID, role, stage, status, detail, localAddr, remoteAddr string, meta map[string]string, counters map[string]int) error {
	if c == nil {
		return nil
	}
	return WritePunchProgress(c, P2PPunchProgress{
		SessionID:  sessionID,
		Role:       role,
		Stage:      stage,
		Status:     status,
		Detail:     detail,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Meta:       meta,
		Counters:   counters,
	})
}

func (s *runtimeSession) sendProgress(stage, status, detail, localAddr, remoteAddr string, meta map[string]string) error {
	if s == nil {
		return nil
	}
	return trySendProgressWithStatus(s.control, s.start.SessionID, s.start.Role, stage, status, detail, localAddr, remoteAddr, s.enrichProgressMeta(localAddr, remoteAddr, meta), s.progressCounters())
}

func trySendAbort(c *conn.Conn, sessionID, role, reason string) error {
	if c == nil {
		return nil
	}
	return WriteBridgeMessage(c, common.P2P_PUNCH_ABORT, P2PPunchAbort{
		SessionID: sessionID,
		Role:      role,
		Reason:    reason,
	})
}

func (s *runtimeSession) startNominationLoop(ctx context.Context, writeConn net.PacketConn, remoteAddr net.Addr) {
	s.startNominationLoopWithEpoch(ctx, writeConn, remoteAddr, 0)
}

func (s *runtimeSession) startNominationLoopWithEpoch(ctx context.Context, writeConn net.PacketConn, remoteAddr net.Addr, epoch uint32) {
	if writeConn == nil || remoteAddr == nil {
		return
	}
	candidateID := candidateKey(writeConn.LocalAddr().String(), remoteAddr.String())
	key := nominationLoopKey(candidateID, epoch)
	s.mu.Lock()
	if s.nominate == nil {
		s.nominate = make(map[string]struct{})
	}
	if _, ok := s.nominate[key]; ok {
		s.mu.Unlock()
		return
	}
	s.nominate[key] = struct{}{}
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.nominate, key)
			s.mu.Unlock()
		}()
		attempt := 0
		for {
			if !sleepContext(ctx, s.nominationRetryDelay(epoch, attempt)) {
				return
			}
			attempt++
			if s.cm.ConfirmedPair() != nil {
				return
			}
			if !s.matchesOutboundNomination(writeConn.LocalAddr().String(), remoteAddr.String(), epoch) {
				return
			}
			if s.shouldRenominate(writeConn.LocalAddr().String(), remoteAddr.String(), epoch) {
				s.tryRenominate(ctx, writeConn.LocalAddr().String(), remoteAddr.String(), epoch)
				return
			}
			if !s.sendNominationBurst(ctx, writeConn, remoteAddr, epoch) {
				return
			}
		}
	}()
}

func (s *runtimeSession) startAcceptLoop(ctx context.Context, writeConn net.PacketConn, remoteAddr net.Addr, epoch uint32) {
	if writeConn == nil || remoteAddr == nil {
		return
	}
	key := nominationLoopKey(candidateKey(writeConn.LocalAddr().String(), remoteAddr.String()), epoch)
	s.mu.Lock()
	if s.accept == nil {
		s.accept = make(map[string]struct{})
	}
	if _, ok := s.accept[key]; ok {
		s.mu.Unlock()
		return
	}
	s.accept[key] = struct{}{}
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.accept, key)
			s.mu.Unlock()
		}()
		attempt := 0
		for {
			if !sleepContext(ctx, s.nominationRetryDelay(epoch, attempt)) {
				return
			}
			attempt++
			if s.cm.ConfirmedPair() != nil {
				return
			}
			if !s.matchesInboundProposal(writeConn.LocalAddr().String(), remoteAddr.String(), epoch) {
				return
			}
			if !s.sendAcceptBurst(ctx, writeConn, remoteAddr, epoch) {
				return
			}
		}
	}()
}

func (s *runtimeSession) scheduleBestNomination(ctx context.Context) {
	if s == nil || s.start.Role != common.WORK_P2P_VISITOR {
		return
	}
	if s.cm.ConfirmedPair() != nil || s.cm.NominatedPair() != nil {
		return
	}
	delay := s.nominationDelay()
	if delay <= 0 {
		s.nominateBestCandidate(ctx)
		return
	}
	s.mu.Lock()
	if s.nominationScheduled {
		s.mu.Unlock()
		return
	}
	s.nominationScheduled = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.nominationScheduled = false
			s.mu.Unlock()
		}()
		if !sleepContext(ctx, delay) {
			return
		}
		s.nominateBestCandidate(ctx)
	}()
}

func (s *runtimeSession) nominateBestCandidate(ctx context.Context) {
	if s == nil || s.start.Role != common.WORK_P2P_VISITOR {
		return
	}
	pair, nominated := s.cm.TryNominateBest()
	if !nominated || pair == nil {
		return
	}
	writeConn := s.socketForLocalAddr(pair.LocalAddr)
	if writeConn == nil {
		_ = s.cm.ReleaseNomination(pair.LocalAddr, pair.RemoteAddr)
		return
	}
	remoteAddr, err := net.ResolveUDPAddr(detectAddrFamily(writeConn.LocalAddr()).network(), pair.RemoteAddr)
	if err != nil {
		_ = s.cm.ReleaseNomination(pair.LocalAddr, pair.RemoteAddr)
		return
	}
	epoch := s.nextOutboundNominationEpoch()
	s.setOutboundNomination(pair.LocalAddr, pair.RemoteAddr, epoch)
	logs.Info("[P2P] candidate nominated local=%s remote=%s score=%d reason=%s successes=%d", pair.LocalAddr, pair.RemoteAddr, pair.Score, pair.ScoreReason, pair.SuccessCount)
	if !s.sendNominationBurst(ctx, writeConn, remoteAddr, epoch) {
		s.clearOutboundNomination(pair.LocalAddr, pair.RemoteAddr, epoch)
		_ = s.cm.ReleaseNomination(pair.LocalAddr, pair.RemoteAddr)
		return
	}
	s.updateCandidateRemote(pair.RemoteAddr)
	logs.Info("[P2P] END sent local=%s remote=%s", pair.LocalAddr, pair.RemoteAddr)
	meta := candidateMeta(pair)
	if meta == nil {
		meta = make(map[string]string, 1)
	}
	meta["nomination_epoch"] = fmt.Sprintf("%d", epoch)
	_ = s.sendProgress("candidate_nominated", "ok", pair.RemoteAddr, pair.LocalAddr, pair.RemoteAddr, meta)
	s.startNominationLoopWithEpoch(ctx, writeConn, remoteAddr, epoch)
}

func (s *runtimeSession) sendControlBurst(ctx context.Context, writeConn net.PacketConn, packetType string, remoteAddr net.Addr, count int, gap time.Duration, epoch uint32) {
	if s == nil || writeConn == nil || remoteAddr == nil || count <= 0 {
		return
	}
	pacer := s.ensurePacer()
	for i := 0; i < count; i++ {
		_ = s.writeUDPToConnWithEpoch(writeConn, packetType, remoteAddr, epoch)
		if i >= count-1 || gap <= 0 {
			continue
		}
		if !sleepContext(ctx, pacer.controlGap(packetType, i, gap)) {
			return
		}
	}
}

func (s *runtimeSession) sendNominationBurst(ctx context.Context, writeConn net.PacketConn, remoteAddr net.Addr, epoch uint32) bool {
	if s == nil || writeConn == nil || remoteAddr == nil {
		return false
	}
	if err := s.writeUDPToConnWithEpoch(writeConn, packetTypePunch, remoteAddr, epoch); err != nil {
		return false
	}
	if !sleepContext(ctx, s.ensurePacer().controlGap(packetTypePunch, int(epoch), controlBurstGap)) {
		return false
	}
	return s.writeUDPToConnWithEpoch(writeConn, packetTypeEnd, remoteAddr, epoch) == nil
}

func (s *runtimeSession) sendAcceptBurst(ctx context.Context, writeConn net.PacketConn, remoteAddr net.Addr, epoch uint32) bool {
	if s == nil || writeConn == nil || remoteAddr == nil {
		return false
	}
	if err := s.writeUDPToConnWithEpoch(writeConn, packetTypeSucc, remoteAddr, epoch); err != nil {
		return false
	}
	if !sleepContext(ctx, s.ensurePacer().controlGap(packetTypeSucc, int(epoch), controlBurstGap)) {
		return false
	}
	return s.writeUDPToConnWithEpoch(writeConn, packetTypeAccept, remoteAddr, epoch) == nil
}

func (s *runtimeSession) sendSuccessBurst(ctx context.Context, writeConn net.PacketConn, remoteAddr net.Addr) bool {
	if s == nil || writeConn == nil || remoteAddr == nil {
		return false
	}
	s.sendControlBurst(ctx, writeConn, packetTypeSucc, remoteAddr, successBurstCount, controlBurstGap, 0)
	return true
}

func (s *runtimeSession) socketForLocalAddr(localAddr string) net.PacketConn {
	for _, socket := range s.snapshotSockets() {
		if socket == nil || addrString(socket.LocalAddr()) != localAddr {
			continue
		}
		return socket
	}
	return nil
}

func (s *runtimeSession) successCandidatePriority(localAddr, remoteAddr string) CandidatePriority {
	if s == nil {
		return CandidatePriority{}
	}
	ranker := s.ensureRanker()
	priority := ranker.ResponsivePriority(remoteAddr)
	if priority.Score > 0 {
		return priority
	}
	return ranker.Priority(localAddr, remoteAddr)
}

func candidateMeta(pair *CandidatePair) map[string]string {
	if pair == nil {
		return nil
	}
	meta := map[string]string{
		"candidate_score":   fmt.Sprintf("%d", pair.Score),
		"candidate_reason":  pair.ScoreReason,
		"candidate_success": fmt.Sprintf("%d", pair.SuccessCount),
	}
	if pair.SucceededAt.IsZero() {
		delete(meta, "candidate_success")
	}
	if meta["candidate_reason"] == "" {
		delete(meta, "candidate_reason")
	}
	if meta["candidate_score"] == "0" {
		delete(meta, "candidate_score")
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

func (s *runtimeSession) enrichProgressMeta(localAddr, remoteAddr string, meta map[string]string) map[string]string {
	if s == nil {
		return meta
	}
	out := cloneStringMap(meta)
	if out == nil {
		out = make(map[string]string)
	}
	if _, ok := out["family"]; !ok {
		if family := progressFamily(localAddr, remoteAddr, s.localConn); family != "" {
			out["family"] = family
		}
	}
	if _, ok := out["candidate_remote"]; !ok {
		if candidateRemote := s.cm.CandidateRemote(); candidateRemote != "" {
			out["candidate_remote"] = candidateRemote
		}
	}
	if _, ok := out["confirmed_remote"]; !ok {
		if confirmedRemote := s.cm.ConfirmedRemote(); confirmedRemote != "" {
			out["confirmed_remote"] = confirmedRemote
		}
	}
	if _, ok := out["rendezvous_remote"]; !ok && s.endpoints.RendezvousRemote != "" {
		out["rendezvous_remote"] = s.endpoints.RendezvousRemote
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func progressFamily(localAddr, remoteAddr string, localConn net.PacketConn) string {
	switch {
	case detectAddressFamily(localAddr) != udpFamilyAny:
		return detectAddressFamily(localAddr).String()
	case detectAddressFamily(remoteAddr) != udpFamilyAny:
		return detectAddressFamily(remoteAddr).String()
	case localConn != nil:
		return detectAddrFamily(localConn.LocalAddr()).String()
	default:
		return ""
	}
}

func effectiveNominationEpoch(packet *UDPPacket) uint32 {
	if packet == nil {
		return 0
	}
	if packet.NominationEpoch != 0 {
		return packet.NominationEpoch
	}
	switch packet.Type {
	case packetTypeEnd, packetTypeAccept, packetTypeReady:
		return 1
	default:
		return 0
	}
}

func nominationLoopKey(candidateID string, epoch uint32) string {
	return fmt.Sprintf("%s|%d", candidateID, epoch)
}

func (s *runtimeSession) nextOutboundNominationEpoch() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextNominationEpoch++
	if s.nextNominationEpoch == 0 {
		s.nextNominationEpoch = 1
	}
	return s.nextNominationEpoch
}

func (s *runtimeSession) setOutboundNomination(localAddr, remoteAddr string, epoch uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outboundNomination = outboundNominationState{
		key:       candidateKey(localAddr, remoteAddr),
		epoch:     epoch,
		startedAt: time.Now(),
	}
}

func (s *runtimeSession) clearOutboundNomination(localAddr, remoteAddr string, epoch uint32) {
	key := candidateKey(localAddr, remoteAddr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outboundNomination.key != key || s.outboundNomination.epoch != epoch {
		return
	}
	s.outboundNomination = outboundNominationState{}
}

func (s *runtimeSession) matchesOutboundNomination(localAddr, remoteAddr string, epoch uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch == 0 {
		return false
	}
	return s.outboundNomination.key == candidateKey(localAddr, remoteAddr) && s.outboundNomination.epoch == epoch
}

func (s *runtimeSession) shouldRenominate(localAddr, remoteAddr string, epoch uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outboundNomination.key != candidateKey(localAddr, remoteAddr) || s.outboundNomination.epoch != epoch {
		return false
	}
	if s.outboundNomination.startedAt.IsZero() {
		return false
	}
	return time.Since(s.outboundNomination.startedAt) >= s.plan.renominationTimeout()
}

func (s *runtimeSession) scheduleNominationRetry(ctx context.Context, delay time.Duration) {
	go func() {
		if !sleepContext(ctx, s.nominationDelayValue(delay)) {
			return
		}
		s.nominateBestCandidate(ctx)
	}()
}

func (s *runtimeSession) tryRenominate(ctx context.Context, localAddr, remoteAddr string, epoch uint32) {
	if !s.matchesOutboundNomination(localAddr, remoteAddr, epoch) {
		return
	}
	_ = s.cm.BackoffNomination(localAddr, remoteAddr, s.plan.renominationCooldown())
	s.clearOutboundNomination(localAddr, remoteAddr, epoch)
	_ = s.sendProgress("candidate_renominate", "ok", remoteAddr, localAddr, remoteAddr, map[string]string{
		"nomination_epoch": fmt.Sprintf("%d", epoch),
	})
	s.nominateBestCandidate(ctx)
	if s.cm.NominatedPair() == nil {
		s.scheduleNominationRetry(ctx, s.plan.renominationCooldown())
	}
}

func (s *runtimeSession) adoptInboundProposal(localAddr, remoteAddr string, epoch uint32) (*CandidatePair, bool) {
	if epoch == 0 {
		return nil, false
	}
	key := candidateKey(localAddr, remoteAddr)
	s.mu.Lock()
	current := s.inboundProposal
	switch {
	case current.epoch > epoch:
		s.mu.Unlock()
		return nil, false
	case current.epoch == epoch && current.key != "" && current.key != key:
		s.mu.Unlock()
		return nil, false
	default:
		s.inboundProposal = inboundProposalState{key: key, epoch: epoch}
		s.mu.Unlock()
	}
	return s.cm.AdoptNomination(localAddr, remoteAddr)
}

func (s *runtimeSession) matchesInboundProposal(localAddr, remoteAddr string, epoch uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch == 0 {
		return false
	}
	return s.inboundProposal.key == candidateKey(localAddr, remoteAddr) && s.inboundProposal.epoch == epoch
}

func (s *runtimeSession) recordTokenMismatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.tokenMismatchDropped++
}

func (s *runtimeSession) recordReplayDrop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.replayDropped++
}

func (s *runtimeSession) recordTokenVerified() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats.tokenVerified {
		return
	}
	s.stats.tokenVerified = true
	logs.Info("[P2P] token verified role=%s session=%s", s.start.Role, s.start.SessionID)
}

func (s *runtimeSession) logTokenStats() {
	stats := s.snapshotStats()
	if stats.tokenMismatchDropped > 0 {
		logs.Info("[P2P] token mismatch silently dropped role=%s count=%d", s.start.Role, stats.tokenMismatchDropped)
	}
	if stats.replayDropped > 0 {
		logs.Info("[P2P] replay silently dropped role=%s count=%d", s.start.Role, stats.replayDropped)
	}
}

func (s *runtimeSession) progressCounters() map[string]int {
	if s == nil {
		return nil
	}
	counts := s.cm.StateCounts()
	stats := s.snapshotStats()
	if counts == nil {
		counts = make(map[string]int)
	}
	counts["token_mismatch_dropped"] = stats.tokenMismatchDropped
	counts["replay_dropped"] = stats.replayDropped
	if stats.tokenVerified {
		counts["token_verified"] = 1
	}
	return counts
}

func (s *runtimeSession) nominationDelay() time.Duration {
	return s.nominationDelayValue(s.plan.nominationDelay())
}

func (s *runtimeSession) nominationDelayValue(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	if pacer := s.ensurePacer(); pacer != nil {
		return pacer.nominationDelay(base)
	}
	return base
}

func (s *runtimeSession) nominationRetryDelay(epoch uint32, attempt int) time.Duration {
	base := s.plan.nominationRetryInterval()
	if pacer := s.ensurePacer(); pacer != nil {
		return pacer.nominationRetryDelay(epoch, attempt, base)
	}
	return base
}

func (s *runtimeSession) acceptReplay(packet *UDPPacket) bool {
	if packet == nil {
		return false
	}
	if s.replay == nil {
		return true
	}
	if s.replay.Accept(packet.Timestamp, packet.Nonce) {
		return true
	}
	s.recordReplayDrop()
	return false
}
