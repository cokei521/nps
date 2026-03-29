package bridge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/p2p"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/server/connection"
	"github.com/djylb/nps/server/p2pstate"
)

type p2pSessionManager struct {
	sessions sync.Map
}

type p2pBridgeSession struct {
	mgr             *p2pSessionManager
	id              string
	token           string
	visitorID       int
	providerID      int
	task            *file.Tunnel
	timeouts        p2p.P2PTimeouts
	visitorControl  *conn.Conn
	providerControl *conn.Conn
	visitorReport   *p2p.P2PProbeReport
	providerReport  *p2p.P2PProbeReport
	visitorStart    p2p.P2PPunchStart
	providerStart   p2p.P2PPunchStart
	timer           *time.Timer
	mu              sync.Mutex
	closed          bool
	summarySent     bool
	visitorReady    bool
	providerReady   bool
	goSent          bool
	telemetry       p2pSessionTelemetry
}

type p2pSessionTelemetry struct {
	createdAt    time.Time
	summaryAt    time.Time
	goAt         time.Time
	outcomeAt    time.Time
	outcome      string
	reason       string
	summaryHints map[string]any
	roles        map[string]*p2pRoleTelemetry
	finalLogged  bool
}

type p2pRoleTelemetry struct {
	LastStage            string
	LastStatus           string
	LastDetail           string
	LastLocalAddr        string
	LastRemoteAddr       string
	LastFamily           string
	TransportMode        string
	TransportEstablished bool
	Counters             map[string]int
	Meta                 map[string]string
	Stages               map[string]*p2pStageTelemetry
}

type p2pStageTelemetry struct {
	FirstAt time.Time
	LastAt  time.Time
	Count   int
	Status  string
	Detail  string
	Family  string
}

type p2pSessionTelemetrySnapshot struct {
	CreatedAtMs  int64                               `json:"created_at_ms,omitempty"`
	SummaryAtMs  int64                               `json:"summary_at_ms,omitempty"`
	GoAtMs       int64                               `json:"go_at_ms,omitempty"`
	OutcomeAtMs  int64                               `json:"outcome_at_ms,omitempty"`
	Outcome      string                              `json:"outcome,omitempty"`
	Reason       string                              `json:"reason,omitempty"`
	SummaryHints map[string]any                      `json:"summary_hints,omitempty"`
	Roles        map[string]p2pRoleTelemetrySnapshot `json:"roles,omitempty"`
}

type p2pRoleTelemetrySnapshot struct {
	LastStage            string                               `json:"last_stage,omitempty"`
	LastStatus           string                               `json:"last_status,omitempty"`
	LastDetail           string                               `json:"last_detail,omitempty"`
	LastLocalAddr        string                               `json:"last_local_addr,omitempty"`
	LastRemoteAddr       string                               `json:"last_remote_addr,omitempty"`
	LastFamily           string                               `json:"last_family,omitempty"`
	TransportMode        string                               `json:"transport_mode,omitempty"`
	TransportEstablished bool                                 `json:"transport_established,omitempty"`
	Counters             map[string]int                       `json:"counters,omitempty"`
	Meta                 map[string]string                    `json:"meta,omitempty"`
	Stages               map[string]p2pStageTelemetrySnapshot `json:"stages,omitempty"`
}

type p2pStageTelemetrySnapshot struct {
	FirstAtMs int64  `json:"first_at_ms,omitempty"`
	LastAtMs  int64  `json:"last_at_ms,omitempty"`
	Count     int    `json:"count,omitempty"`
	Status    string `json:"status,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Family    string `json:"family,omitempty"`
}

func newP2PSessionManager() *p2pSessionManager {
	return &p2pSessionManager{}
}

func newP2PSessionTelemetry(now time.Time) p2pSessionTelemetry {
	return p2pSessionTelemetry{
		createdAt: now,
		roles:     make(map[string]*p2pRoleTelemetry, 2),
	}
}

func (t *p2pSessionTelemetry) ensureRole(role string) *p2pRoleTelemetry {
	if t.roles == nil {
		t.roles = make(map[string]*p2pRoleTelemetry, 2)
	}
	telemetry := t.roles[role]
	if telemetry != nil {
		return telemetry
	}
	telemetry = &p2pRoleTelemetry{
		Counters: make(map[string]int),
		Meta:     make(map[string]string),
		Stages:   make(map[string]*p2pStageTelemetry),
	}
	t.roles[role] = telemetry
	return telemetry
}

func (t *p2pSessionTelemetry) recordProgress(progress p2p.P2PPunchProgress) {
	if progress.Role == "" {
		return
	}
	at := time.UnixMilli(progress.Timestamp)
	if progress.Timestamp == 0 {
		at = time.Now()
	}
	role := t.ensureRole(progress.Role)
	role.LastStage = progress.Stage
	role.LastStatus = progress.Status
	role.LastDetail = progress.Detail
	role.LastLocalAddr = progress.LocalAddr
	role.LastRemoteAddr = progress.RemoteAddr
	role.LastFamily = progressFamily(progress)
	if mode := progressTransportMode(progress); mode != "" {
		role.TransportMode = mode
	}
	if progress.Stage == "transport_established" && progress.Status != "fail" {
		role.TransportEstablished = true
	}
	if len(progress.Counters) > 0 {
		role.Counters = cloneIntMap(progress.Counters)
	}
	role.Meta = mergeStringMaps(role.Meta, progress.Meta)
	stage := role.Stages[progress.Stage]
	if stage == nil {
		stage = &p2pStageTelemetry{FirstAt: at}
		role.Stages[progress.Stage] = stage
	}
	if stage.FirstAt.IsZero() {
		stage.FirstAt = at
	}
	stage.LastAt = at
	stage.Count++
	stage.Status = progress.Status
	stage.Detail = progress.Detail
	stage.Family = progressFamily(progress)
}

func (t *p2pSessionTelemetry) recordSummary(hints map[string]any, at time.Time) {
	t.summaryHints = cloneAnyMap(hints)
	t.summaryAt = at
}

func (t *p2pSessionTelemetry) recordGo(at time.Time) {
	t.goAt = at
}

func (t *p2pSessionTelemetry) maybeFinalizeSuccess(at time.Time) (p2pSessionTelemetrySnapshot, bool) {
	if t.finalLogged {
		return p2pSessionTelemetrySnapshot{}, false
	}
	if !t.allTransportEstablished() {
		return p2pSessionTelemetrySnapshot{}, false
	}
	t.outcome = "transport_established"
	t.outcomeAt = at
	t.finalLogged = true
	return t.snapshot(), true
}

func (t *p2pSessionTelemetry) roleTransportEstablished(role string) bool {
	if t == nil || role == "" {
		return false
	}
	telemetry := t.roles[role]
	return telemetry != nil && telemetry.TransportEstablished
}

func (t *p2pSessionTelemetry) allTransportEstablished() bool {
	if t == nil {
		return false
	}
	visitor := t.roles[common.WORK_P2P_VISITOR]
	provider := t.roles[common.WORK_P2P_PROVIDER]
	return visitor != nil && provider != nil && visitor.TransportEstablished && provider.TransportEstablished
}

func (t *p2pSessionTelemetry) finalizeOutcome(outcome, reason string, at time.Time) (p2pSessionTelemetrySnapshot, bool) {
	if t.finalLogged {
		return p2pSessionTelemetrySnapshot{}, false
	}
	t.outcome = outcome
	t.reason = reason
	t.outcomeAt = at
	t.finalLogged = true
	return t.snapshot(), true
}

func (t *p2pSessionTelemetry) snapshot() p2pSessionTelemetrySnapshot {
	snapshot := p2pSessionTelemetrySnapshot{
		CreatedAtMs:  timestampMillis(t.createdAt),
		SummaryAtMs:  timestampMillis(t.summaryAt),
		GoAtMs:       timestampMillis(t.goAt),
		OutcomeAtMs:  timestampMillis(t.outcomeAt),
		Outcome:      t.outcome,
		Reason:       t.reason,
		SummaryHints: cloneAnyMap(t.summaryHints),
		Roles:        make(map[string]p2pRoleTelemetrySnapshot, len(t.roles)),
	}
	for role, telemetry := range t.roles {
		if telemetry == nil {
			continue
		}
		roleSnapshot := p2pRoleTelemetrySnapshot{
			LastStage:            telemetry.LastStage,
			LastStatus:           telemetry.LastStatus,
			LastDetail:           telemetry.LastDetail,
			LastLocalAddr:        telemetry.LastLocalAddr,
			LastRemoteAddr:       telemetry.LastRemoteAddr,
			LastFamily:           telemetry.LastFamily,
			TransportMode:        telemetry.TransportMode,
			TransportEstablished: telemetry.TransportEstablished,
			Counters:             cloneIntMap(telemetry.Counters),
			Meta:                 cloneStringMap(telemetry.Meta),
			Stages:               make(map[string]p2pStageTelemetrySnapshot, len(telemetry.Stages)),
		}
		for stage, details := range telemetry.Stages {
			if details == nil {
				continue
			}
			roleSnapshot.Stages[stage] = p2pStageTelemetrySnapshot{
				FirstAtMs: timestampMillis(details.FirstAt),
				LastAtMs:  timestampMillis(details.LastAt),
				Count:     details.Count,
				Status:    details.Status,
				Detail:    details.Detail,
				Family:    details.Family,
			}
		}
		snapshot.Roles[role] = roleSnapshot
	}
	return snapshot
}

func timestampMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func cloneIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
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

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func mergeStringMaps(current, update map[string]string) map[string]string {
	if len(current) == 0 && len(update) == 0 {
		return nil
	}
	out := cloneStringMap(current)
	if out == nil {
		out = make(map[string]string, len(update))
	}
	for key, value := range update {
		out[key] = value
	}
	return out
}

func progressFamily(progress p2p.P2PPunchProgress) string {
	if progress.Meta != nil && progress.Meta["family"] != "" {
		return progress.Meta["family"]
	}
	if ip := net.ParseIP(strings.Trim(common.GetIpByAddr(progress.LocalAddr), "[]")); ip != nil {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	if ip := net.ParseIP(strings.Trim(common.GetIpByAddr(progress.RemoteAddr), "[]")); ip != nil {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return ""
}

func progressTransportMode(progress p2p.P2PPunchProgress) string {
	if progress.Meta != nil && progress.Meta["transport_mode"] != "" {
		return progress.Meta["transport_mode"]
	}
	if progress.Stage == "transport_established" || progress.Stage == "transport_start" || progress.Stage == "handover_begin" {
		return progress.Detail
	}
	return ""
}

func logP2PSessionTelemetry(sessionID string, snapshot p2pSessionTelemetrySnapshot) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		logs.Info("[P2P] session=%s telemetry marshal failed: %v", sessionID, err)
		return
	}
	logs.Info("[P2P] session=%s telemetry=%s", sessionID, raw)
}

func (m *p2pSessionManager) create(visitorID, providerID int, task *file.Tunnel, visitorControl *conn.Conn, visitorProbe, providerProbe p2p.P2PProbeConfig) (*p2pBridgeSession, error) {
	if !p2p.HasUsableProbeEndpoint(visitorProbe) || !p2p.HasUsableProbeEndpoint(providerProbe) {
		return nil, fmt.Errorf("p2p probe endpoint is not configured")
	}
	sessionID := crypt.GenerateUUID(strconv.Itoa(visitorID), strconv.Itoa(providerID), task.Password, time.Now().String()).String()
	token, err := generateP2PSessionToken()
	if err != nil {
		return nil, err
	}
	wire, err := p2p.NewP2PWireSpec()
	if err != nil {
		return nil, err
	}
	timeouts := loadP2PTimeouts()
	ttl := sessionTTL(timeouts)
	session := &p2pBridgeSession{
		mgr:            m,
		id:             sessionID,
		token:          token,
		visitorID:      visitorID,
		providerID:     providerID,
		task:           task,
		timeouts:       timeouts,
		visitorControl: visitorControl,
		visitorStart: p2p.P2PPunchStart{
			SessionID: sessionID,
			Token:     token,
			Wire:      wire,
			Role:      common.WORK_P2P_VISITOR,
			PeerRole:  common.WORK_P2P_PROVIDER,
			Probe:     visitorProbe,
			Timeouts:  timeouts,
		},
		providerStart: p2p.P2PPunchStart{
			SessionID: sessionID,
			Token:     token,
			Wire:      wire,
			Role:      common.WORK_P2P_PROVIDER,
			PeerRole:  common.WORK_P2P_VISITOR,
			Probe:     providerProbe,
			Timeouts:  timeouts,
		},
		telemetry: newP2PSessionTelemetry(time.Now()),
	}
	session.timer = time.AfterFunc(ttl, func() {
		session.abort("session timeout")
	})
	m.sessions.Store(sessionID, session)
	p2pstate.Register(sessionID, wire, token, ttl)
	return session, nil
}

func (m *p2pSessionManager) get(sessionID string) (*p2pBridgeSession, bool) {
	value, ok := m.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	session, ok := value.(*p2pBridgeSession)
	if !ok || session == nil {
		m.sessions.Delete(sessionID)
		return nil, false
	}
	session.mu.Lock()
	closed := session.closed
	session.mu.Unlock()
	if closed {
		m.sessions.Delete(sessionID)
		return nil, false
	}
	return session, true
}

func (s *p2pBridgeSession) attachProvider(control *conn.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.providerControl != nil && s.providerControl != control {
		return false
	}
	s.providerControl = control
	return true
}

func (s *p2pBridgeSession) serve(role string, control *conn.Conn) {
	for {
		flag, err := control.ReadFlag()
		if err != nil {
			s.abortPending(role, fmt.Sprintf("%s control closed", role))
			return
		}
		switch flag {
		case common.P2P_PROBE_REPORT:
			raw, err := control.GetShortLenContent()
			if err != nil {
				s.abortPending(role, fmt.Sprintf("%s report read failed", role))
				continue
			}
			var report p2p.P2PProbeReport
			if err := json.Unmarshal(raw, &report); err != nil {
				s.abortPending(role, fmt.Sprintf("%s report decode failed", role))
				continue
			}
			s.handleReport(role, &report)
		case common.P2P_PUNCH_PROGRESS:
			raw, err := control.GetShortLenContent()
			if err != nil {
				continue
			}
			var progress p2p.P2PPunchProgress
			if err := json.Unmarshal(raw, &progress); err != nil {
				continue
			}
			s.handleProgress(&progress)
		case common.P2P_PUNCH_READY:
			raw, err := control.GetShortLenContent()
			if err != nil {
				s.abortPending(role, fmt.Sprintf("%s ready read failed", role))
				continue
			}
			var ready p2p.P2PPunchReady
			if err := json.Unmarshal(raw, &ready); err != nil {
				s.abortPending(role, fmt.Sprintf("%s ready decode failed", role))
				continue
			}
			s.handleReady(role, &ready)
		case common.P2P_PUNCH_ABORT:
			raw, err := control.GetShortLenContent()
			if err != nil {
				s.abortPending(role, fmt.Sprintf("%s abort read failed", role))
				continue
			}
			var abort p2p.P2PPunchAbort
			if err := json.Unmarshal(raw, &abort); err != nil {
				s.abortPending(role, fmt.Sprintf("%s abort decode failed", role))
				continue
			}
			s.abort(abort.Reason)
		default:
			if _, err := control.GetShortLenContent(); err != nil {
				return
			}
		}
	}
}

func (s *p2pBridgeSession) handleProgress(progress *p2p.P2PPunchProgress) {
	if progress == nil {
		return
	}
	s.mu.Lock()
	if s.telemetry.createdAt.IsZero() {
		s.telemetry = newP2PSessionTelemetry(time.Now())
	}
	if s.closed || progress.SessionID != s.id {
		s.mu.Unlock()
		return
	}
	s.telemetry.recordProgress(*progress)
	snapshot, finalized := s.telemetry.maybeFinalizeSuccess(time.Now())
	s.mu.Unlock()

	logs.Info("[P2P] session=%s role=%s stage=%s status=%s local=%s remote=%s detail=%s meta=%v counters=%v",
		progress.SessionID, progress.Role, progress.Stage, progress.Status, progress.LocalAddr, progress.RemoteAddr, progress.Detail, progress.Meta, progress.Counters)
	if finalized {
		s.finishTransportEstablished()
		logP2PSessionTelemetry(s.id, snapshot)
	}
}

func (s *p2pBridgeSession) finishTransportEstablished() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	visitorControl := s.visitorControl
	providerControl := s.providerControl
	s.visitorControl = nil
	s.providerControl = nil
	s.mu.Unlock()

	if visitorControl != nil {
		_ = visitorControl.Close()
	}
	if providerControl != nil {
		_ = providerControl.Close()
	}
	if s.mgr != nil {
		s.mgr.sessions.Delete(s.id)
	}
}

func (s *p2pBridgeSession) handleReport(role string, report *p2p.P2PProbeReport) {
	s.mu.Lock()
	if s.closed || report == nil || report.SessionID != s.id || report.Token != s.token {
		s.mu.Unlock()
		return
	}
	switch role {
	case common.WORK_P2P_VISITOR:
		s.visitorReport = report
	case common.WORK_P2P_PROVIDER:
		s.providerReport = report
	}
	ready := s.visitorReport != nil && s.providerReport != nil
	s.mu.Unlock()
	if ready {
		s.sendSummary()
	}
}

func (s *p2pBridgeSession) handleReady(role string, ready *p2p.P2PPunchReady) {
	s.mu.Lock()
	if s.closed || ready == nil || ready.SessionID != s.id || !s.summarySent {
		s.mu.Unlock()
		return
	}
	switch role {
	case common.WORK_P2P_VISITOR:
		s.visitorReady = true
	case common.WORK_P2P_PROVIDER:
		s.providerReady = true
	}
	readyToGo := s.visitorReady && s.providerReady && !s.goSent
	s.mu.Unlock()
	if readyToGo {
		s.sendGo()
	}
}

func (s *p2pBridgeSession) sendSummary() {
	s.mu.Lock()
	if s.closed || s.summarySent || s.visitorReport == nil || s.providerReport == nil {
		s.mu.Unlock()
		return
	}
	visitorSelf := mergeProbeObservation(s.id, s.visitorReport.Self)
	providerSelf := mergeProbeObservation(s.id, s.providerReport.Self)
	visitorSummary := p2p.P2PProbeSummary{
		SessionID: s.id,
		Token:     s.token,
		Role:      common.WORK_P2P_VISITOR,
		PeerRole:  common.WORK_P2P_PROVIDER,
		Self:      visitorSelf,
		Peer:      providerSelf,
		Timeouts:  s.timeouts,
		Hints:     buildSummaryHints(visitorSelf, providerSelf),
	}
	providerSummary := p2p.P2PProbeSummary{
		SessionID: s.id,
		Token:     s.token,
		Role:      common.WORK_P2P_PROVIDER,
		PeerRole:  common.WORK_P2P_VISITOR,
		Self:      providerSelf,
		Peer:      visitorSelf,
		Timeouts:  s.timeouts,
		Hints:     visitorSummary.Hints,
	}
	visitorControl := s.visitorControl
	providerControl := s.providerControl
	s.summarySent = true
	if s.telemetry.createdAt.IsZero() {
		s.telemetry = newP2PSessionTelemetry(time.Now())
	}
	s.telemetry.recordSummary(visitorSummary.Hints, time.Now())
	s.mu.Unlock()

	if visitorControl != nil {
		if err := p2p.WriteBridgeMessage(visitorControl, common.P2P_PROBE_SUMMARY, visitorSummary); err != nil {
			s.abort("send visitor summary failed")
			return
		}
	}
	if providerControl != nil {
		if err := p2p.WriteBridgeMessage(providerControl, common.P2P_PROBE_SUMMARY, providerSummary); err != nil {
			s.abort("send provider summary failed")
			return
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	postSummaryTimeout := postSummaryTTL(s.timeouts)
	if s.timer == nil {
		s.timer = time.AfterFunc(postSummaryTimeout, func() {
			s.abort("post-summary timeout")
		})
	} else {
		s.timer.Reset(postSummaryTimeout)
	}
	s.mu.Unlock()
	logs.Info("[P2P] session=%s summary sent via bridge", s.id)
	p2pstate.Unregister(s.id)
}

func (s *p2pBridgeSession) sendGo() {
	s.mu.Lock()
	if s.closed || !s.summarySent || s.goSent {
		s.mu.Unlock()
		return
	}
	visitorControl := s.visitorControl
	providerControl := s.providerControl
	delayMs := punchGoDelayMs(s.timeouts, s.telemetry.summaryHints)
	goMsg := p2p.P2PPunchGo{
		SessionID: s.id,
		DelayMs:   delayMs,
		SentAtMs:  time.Now().UnixMilli(),
	}
	s.goSent = true
	if s.telemetry.createdAt.IsZero() {
		s.telemetry = newP2PSessionTelemetry(time.Now())
	}
	s.telemetry.recordGo(time.Now())
	s.mu.Unlock()

	if visitorControl != nil {
		msg := goMsg
		msg.Role = common.WORK_P2P_VISITOR
		if err := p2p.WriteBridgeMessage(visitorControl, common.P2P_PUNCH_GO, msg); err != nil {
			s.abort("send visitor punch go failed")
			return
		}
	}
	if providerControl != nil {
		msg := goMsg
		msg.Role = common.WORK_P2P_PROVIDER
		if err := p2p.WriteBridgeMessage(providerControl, common.P2P_PUNCH_GO, msg); err != nil {
			s.abort("send provider punch go failed")
			return
		}
	}
	logs.Info("[P2P] session=%s punch go sent delay=%dms", s.id, delayMs)
}

func (s *p2pBridgeSession) abort(reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	visitorControl := s.visitorControl
	providerControl := s.providerControl
	s.visitorControl = nil
	s.providerControl = nil
	if s.telemetry.createdAt.IsZero() {
		s.telemetry = newP2PSessionTelemetry(time.Now())
	}
	snapshot, logTelemetry := s.telemetry.finalizeOutcome("aborted", reason, time.Now())
	s.mu.Unlock()

	p2pstate.Unregister(s.id)
	if s.mgr != nil {
		s.mgr.sessions.Delete(s.id)
	}
	if visitorControl != nil {
		_ = p2p.WriteBridgeMessage(visitorControl, common.P2P_PUNCH_ABORT, p2p.P2PPunchAbort{
			SessionID: s.id,
			Role:      common.WORK_P2P_VISITOR,
			Reason:    reason,
		})
		_ = visitorControl.Close()
	}
	if providerControl != nil {
		_ = p2p.WriteBridgeMessage(providerControl, common.P2P_PUNCH_ABORT, p2p.P2PPunchAbort{
			SessionID: s.id,
			Role:      common.WORK_P2P_PROVIDER,
			Reason:    reason,
		})
		_ = providerControl.Close()
	}
	if logTelemetry {
		logP2PSessionTelemetry(s.id, snapshot)
	}
}

func (s *p2pBridgeSession) abortPending(role, reason string) {
	s.mu.Lock()
	roleEstablished := s.telemetry.roleTransportEstablished(role)
	shouldAbort := !s.closed && (!s.summarySent || !s.goSent || !roleEstablished)
	s.mu.Unlock()
	if shouldAbort {
		s.abort(reason)
	}
}

func (s *p2pBridgeSession) telemetrySnapshot() p2pSessionTelemetrySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.telemetry.createdAt.IsZero() {
		return p2pSessionTelemetrySnapshot{}
	}
	return s.telemetry.snapshot()
}

func buildProbeConfig(c *conn.Conn) p2p.P2PProbeConfig {
	settings := servercfg.Current()
	expectExtraReply := settings.P2P.ProbeExtraReply
	cfg := p2p.P2PProbeConfig{
		Version:          2,
		Provider:         p2p.ProbeProviderNPS,
		Mode:             p2p.ProbeModeUDP,
		Network:          p2p.ProbeNetworkUDP,
		ExpectExtraReply: expectExtraReply,
		Options:          buildProbeOptions(),
	}
	baseHosts := collectProbeBaseHosts(c)
	endpoints := make([]p2p.P2PProbeEndpoint, 0, len(baseHosts)*3+len(configuredSTUNServers()))
	if connection.P2pPort > 0 {
		for hostIndex, host := range baseHosts {
			for i := 0; i < 3; i++ {
				endpoints = append(endpoints, p2p.P2PProbeEndpoint{
					ID:       fmt.Sprintf("probe-%d-%d", hostIndex+1, i+1),
					Provider: p2p.ProbeProviderNPS,
					Mode:     p2p.ProbeModeUDP,
					Network:  p2p.ProbeNetworkUDP,
					Address:  common.BuildAddress(host, strconv.Itoa(connection.P2pPort+i)),
				})
			}
		}
	}
	for i, addr := range configuredSTUNServers() {
		endpoints = append(endpoints, p2p.P2PProbeEndpoint{
			ID:       fmt.Sprintf("stun-%d", i+1),
			Provider: p2p.ProbeProviderSTUN,
			Mode:     p2p.ProbeModeBinding,
			Network:  p2p.ProbeNetworkUDP,
			Address:  addr,
		})
	}
	cfg.Endpoints = endpoints
	if connection.P2pPort > 0 {
		cfg.Options["base_port"] = strconv.Itoa(connection.P2pPort)
	}
	return cfg
}

func collectProbeBaseHosts(c *conn.Conn) []string {
	hosts := make([]string, 0, 3)
	seen := make(map[string]struct{}, 4)
	addHost := func(host string) {
		host = strings.TrimSpace(host)
		host = strings.Trim(host, "[]")
		if host == "" {
			return
		}
		if ip := net.ParseIP(host); ip != nil {
			ip = common.NormalizeIP(ip)
			if ip == nil || common.IsZeroIP(ip) || ip.IsUnspecified() {
				return
			}
			host = ip.String()
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	addResolvedHosts := func(host string) {
		addHost(host)
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if host == "" || net.ParseIP(host) != nil {
			return
		}
		resolveCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
		if err != nil {
			return
		}
		for _, addr := range addrs {
			addHost(addr.IP.String())
		}
	}

	if c != nil && c.Conn != nil {
		addHost(common.GetIpByAddr(c.LocalAddr().String()))
	}
	addResolvedHosts(strings.TrimSpace(connection.P2pIp))
	addResolvedHosts(common.GetServerIp(connection.P2pIp))
	return hosts
}

func mergeProbeObservation(sessionID string, self p2p.P2PPeerInfo) p2p.P2PPeerInfo {
	serverSamples := p2pstate.GetObservations(sessionID, self.Role)
	if len(serverSamples) == 0 && len(self.Families) == 0 {
		return self
	}
	families := p2p.NormalizePeerFamilyInfos(self)
	if len(families) == 0 {
		combinedSamples := p2p.MergeProbeSamples(serverSamples, self.Nat.Samples)
		mergedNat := p2p.BuildNatObservationWithEvidence(combinedSamples, self.Nat.FilteringTested && !self.Nat.ProbePortRestricted, self.Nat.FilteringTested)
		if self.Nat.MappingConfidenceLow {
			mergedNat.MappingConfidenceLow = true
		}
		mergedNat.ConflictingSignals = mergedNat.ConflictingSignals || self.Nat.ConflictingSignals
		if self.Nat.PortMapping != nil {
			mergedNat.PortMapping = self.Nat.PortMapping
		}
		self.Nat = mergedNat
		return self
	}
	mergedFamilies := make([]p2p.P2PFamilyInfo, 0, len(families))
	for _, family := range families {
		familySamples := p2p.FilterProbeSamplesByFamily(serverSamples, family.Family)
		combinedSamples := p2p.MergeProbeSamples(familySamples, family.Nat.Samples)
		mergedNat := p2p.BuildNatObservationWithEvidence(combinedSamples, family.Nat.FilteringTested && !family.Nat.ProbePortRestricted, family.Nat.FilteringTested)
		if family.Nat.MappingConfidenceLow {
			mergedNat.MappingConfidenceLow = true
		}
		mergedNat.ConflictingSignals = mergedNat.ConflictingSignals || family.Nat.ConflictingSignals
		if family.Nat.PortMapping != nil {
			mergedNat.PortMapping = family.Nat.PortMapping
		}
		family.Nat = mergedNat
		mergedFamilies = append(mergedFamilies, family)
	}
	return p2p.BuildPeerInfo(self.Role, self.TransportMode, self.TransportData, mergedFamilies)
}

func generateP2PSessionToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func buildSummaryHints(self, peer p2p.P2PPeerInfo) map[string]any {
	sharedFamilies := sharedPeerFamilies(self, peer)
	return map[string]any{
		"probe_port_restricted":     self.Nat.ProbePortRestricted || peer.Nat.ProbePortRestricted,
		"mapping_confidence_low":    self.Nat.MappingConfidenceLow || peer.Nat.MappingConfidenceLow,
		"filtering_likely":          self.Nat.ProbePortRestricted || peer.Nat.ProbePortRestricted,
		"self_probe_ip_count":       self.Nat.ProbeIPCount,
		"peer_probe_ip_count":       peer.Nat.ProbeIPCount,
		"self_probe_endpoint_count": self.Nat.ProbeEndpointCount,
		"peer_probe_endpoint_count": peer.Nat.ProbeEndpointCount,
		"self_filtering_tested":     self.Nat.FilteringTested,
		"peer_filtering_tested":     peer.Nat.FilteringTested,
		"self_conflicting_signals":  self.Nat.ConflictingSignals,
		"peer_conflicting_signals":  peer.Nat.ConflictingSignals,
		"self_port_mapping_method":  portMappingMethod(self.Nat.PortMapping),
		"peer_port_mapping_method":  portMappingMethod(peer.Nat.PortMapping),
		"self_probe_provider_count": probeProviderCount(self.Nat.Samples),
		"peer_probe_provider_count": probeProviderCount(peer.Nat.Samples),
		"self_observed_base_port":   self.Nat.ObservedBasePort,
		"self_observed_interval":    self.Nat.ObservedInterval,
		"self_mapping_behavior":     self.Nat.MappingBehavior,
		"self_filtering_behavior":   self.Nat.FilteringBehavior,
		"self_classification_level": self.Nat.ClassificationLevel,
		"peer_observed_base_port":   peer.Nat.ObservedBasePort,
		"peer_observed_interval":    peer.Nat.ObservedInterval,
		"peer_mapping_behavior":     peer.Nat.MappingBehavior,
		"peer_filtering_behavior":   peer.Nat.FilteringBehavior,
		"peer_classification_level": peer.Nat.ClassificationLevel,
		"self_family_count":         len(p2p.NormalizePeerFamilyInfos(self)),
		"peer_family_count":         len(p2p.NormalizePeerFamilyInfos(peer)),
		"shared_family_count":       len(sharedFamilies),
		"shared_families":           sharedFamilies,
		"dual_stack_parallel":       len(sharedFamilies) > 1,
		"self_family_details":       buildPeerFamilyHints(self),
		"peer_family_details":       buildPeerFamilyHints(peer),
	}
}

func buildProbeOptions() map[string]string {
	cfg := servercfg.Current()
	return map[string]string{
		"layout":                       "triple-port",
		"probe_extra_reply":            strconv.FormatBool(cfg.P2P.ProbeExtraReply),
		"force_predict_on_restricted":  strconv.FormatBool(cfg.P2P.ForcePredictOnRestricted),
		"enable_target_spray":          strconv.FormatBool(cfg.P2P.EnableTargetSpray),
		"enable_birthday_attack":       strconv.FormatBool(cfg.P2P.EnableBirthdayAttack),
		"enable_upnp_portmap":          strconv.FormatBool(cfg.P2P.EnableUPNPPortmap),
		"enable_pcp_portmap":           strconv.FormatBool(cfg.P2P.EnablePCPPortmap),
		"enable_natpmp_portmap":        strconv.FormatBool(cfg.P2P.EnableNATPMPPortmap),
		"portmap_lease_seconds":        strconv.Itoa(cfg.P2P.PortmapLeaseSeconds),
		"default_prediction_interval":  strconv.Itoa(cfg.P2P.DefaultPredictionInterval),
		"target_spray_span":            strconv.Itoa(cfg.P2P.TargetSpraySpan),
		"target_spray_rounds":          strconv.Itoa(cfg.P2P.TargetSprayRounds),
		"target_spray_burst":           strconv.Itoa(cfg.P2P.TargetSprayBurst),
		"target_spray_packet_sleep_ms": strconv.Itoa(cfg.P2P.TargetSprayPacketSleepMs),
		"target_spray_burst_gap_ms":    strconv.Itoa(cfg.P2P.TargetSprayBurstGapMs),
		"target_spray_phase_gap_ms":    strconv.Itoa(cfg.P2P.TargetSprayPhaseGapMs),
		"birthday_listen_ports":        strconv.Itoa(cfg.P2P.BirthdayListenPorts),
		"birthday_targets_per_port":    strconv.Itoa(cfg.P2P.BirthdayTargetsPerPort),
	}
}

func loadP2PTimeouts() p2p.P2PTimeouts {
	cfg := servercfg.Current()
	return p2p.P2PTimeouts{
		ProbeTimeoutMs:     cfg.P2P.ProbeTimeoutMs,
		HandshakeTimeoutMs: cfg.P2P.HandshakeTimeoutMs,
		TransportTimeoutMs: cfg.P2P.TransportTimeoutMs,
	}
}

func sessionTTL(timeouts p2p.P2PTimeouts) time.Duration {
	ttl := time.Duration(timeouts.ProbeTimeoutMs+timeouts.HandshakeTimeoutMs+5000) * time.Millisecond
	if ttl < 30*time.Second {
		return 30 * time.Second
	}
	return ttl
}

func postSummaryTTL(timeouts p2p.P2PTimeouts) time.Duration {
	if timeouts.HandshakeTimeoutMs <= 0 || timeouts.TransportTimeoutMs <= 0 {
		return 20 * time.Second
	}
	ttl := time.Duration(timeouts.HandshakeTimeoutMs+timeouts.TransportTimeoutMs)*time.Millisecond + time.Second
	if ttl < 500*time.Millisecond {
		return 500 * time.Millisecond
	}
	return ttl
}

func punchGoDelayMs(timeouts p2p.P2PTimeouts, hints map[string]any) int {
	delay := 120
	if summaryHintInt(hints, "shared_family_count") > 1 {
		delay -= 15
	}
	if summaryHintBool(hints, "mapping_confidence_low") {
		delay += 25
	}
	if summaryHintBool(hints, "probe_port_restricted") {
		delay += 20
	}
	if !summaryHintBool(hints, "self_filtering_tested") || !summaryHintBool(hints, "peer_filtering_tested") {
		delay += 15
	}
	if summaryHintInt(hints, "self_probe_provider_count") > 1 && summaryHintInt(hints, "peer_probe_provider_count") > 1 {
		delay -= 10
	}
	if timeouts.HandshakeTimeoutMs > 0 {
		maxDelay := timeouts.HandshakeTimeoutMs / 5
		if maxDelay > 0 && delay > maxDelay {
			delay = maxDelay
		}
	}
	if delay < 40 {
		delay = 40
	}
	return delay
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

func summaryHintBool(hints map[string]any, key string) bool {
	if len(hints) == 0 {
		return false
	}
	value, ok := hints[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(typed)
		return err == nil && parsed
	default:
		return false
	}
}

func portMappingMethod(info *p2p.PortMappingInfo) string {
	if info == nil {
		return ""
	}
	return info.Method
}

func configuredSTUNServers() []string {
	return p2p.ParseSTUNServerList(servercfg.Current().P2P.STUNServers)
}

func probeProviderCount(samples []p2p.ProbeSample) int {
	if len(samples) == 0 {
		return 0
	}
	providers := make(map[string]struct{}, len(samples))
	for _, sample := range samples {
		provider := sample.Provider
		if provider == "" {
			provider = p2p.ProbeProviderNPS
		}
		providers[provider] = struct{}{}
	}
	return len(providers)
}

func buildPeerFamilyHints(peer p2p.P2PPeerInfo) map[string]map[string]any {
	families := p2p.NormalizePeerFamilyInfos(peer)
	if len(families) == 0 {
		return nil
	}
	out := make(map[string]map[string]any, len(families))
	for _, family := range families {
		out[family.Family] = map[string]any{
			"nat_type":               family.Nat.NATType,
			"mapping_behavior":       family.Nat.MappingBehavior,
			"filtering_behavior":     family.Nat.FilteringBehavior,
			"classification_level":   family.Nat.ClassificationLevel,
			"probe_ip_count":         family.Nat.ProbeIPCount,
			"probe_endpoint_count":   family.Nat.ProbeEndpointCount,
			"probe_provider_count":   probeProviderCount(family.Nat.Samples),
			"observed_base_port":     family.Nat.ObservedBasePort,
			"observed_interval":      family.Nat.ObservedInterval,
			"mapping_confidence_low": family.Nat.MappingConfidenceLow,
			"filtering_tested":       family.Nat.FilteringTested,
			"port_mapping_method":    portMappingMethod(family.Nat.PortMapping),
			"sample_count":           len(family.Nat.Samples),
		}
	}
	return out
}

func sharedPeerFamilies(left, right p2p.P2PPeerInfo) []string {
	leftFamilies := p2p.NormalizePeerFamilyInfos(left)
	rightFamilies := p2p.NormalizePeerFamilyInfos(right)
	if len(leftFamilies) == 0 || len(rightFamilies) == 0 {
		return nil
	}
	rightSet := make(map[string]struct{}, len(rightFamilies))
	for _, family := range rightFamilies {
		if family.Family != "" {
			rightSet[family.Family] = struct{}{}
		}
	}
	shared := make([]string, 0, len(leftFamilies))
	for _, family := range leftFamilies {
		if family.Family == "" {
			continue
		}
		if _, ok := rightSet[family.Family]; ok {
			shared = append(shared, family.Family)
		}
	}
	sort.Strings(shared)
	return shared
}
