package p2pstate

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/p2p"
)

type probeSession struct {
	mu           sync.Mutex
	sessionID    string
	routeKey     string
	token        string
	expiresAt    time.Time
	observations map[string]map[string]p2p.ProbeSample
	replay       *p2p.ReplayWindow
}

var (
	probeSessionsByID    sync.Map
	probeSessionsByRoute sync.Map
	cleanerOnce          sync.Once
)

func Register(sessionID string, wire p2p.P2PWireSpec, token string, ttl time.Duration) {
	if sessionID == "" || token == "" {
		return
	}
	routeKey := p2p.WireRouteKey(p2p.NormalizeP2PWireSpec(wire, sessionID).RouteID)
	if routeKey == "" {
		return
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	startCleaner()
	session := &probeSession{
		sessionID:    sessionID,
		routeKey:     routeKey,
		token:        token,
		expiresAt:    time.Now().Add(ttl),
		observations: make(map[string]map[string]p2p.ProbeSample),
		replay:       p2p.NewReplayWindow(30 * time.Second),
	}
	probeSessionsByID.Store(sessionID, session)
	probeSessionsByRoute.Store(routeKey, session)
}

func Unregister(sessionID string) {
	if sessionID == "" {
		return
	}
	session := getByID(sessionID)
	if session != nil && session.routeKey != "" {
		probeSessionsByRoute.Delete(session.routeKey)
	}
	probeSessionsByID.Delete(sessionID)
}

func ValidateToken(sessionID, token string) bool {
	session := getByID(sessionID)
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if time.Now().After(session.expiresAt) {
		deleteSession(session)
		return false
	}
	return session.token == token
}

func LookupSession(routeKey string) (p2p.UDPPacketLookupResult, bool) {
	session := getByRoute(routeKey)
	if session == nil {
		return p2p.UDPPacketLookupResult{}, false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if time.Now().After(session.expiresAt) {
		deleteSession(session)
		return p2p.UDPPacketLookupResult{}, false
	}
	if session.token == "" {
		return p2p.UDPPacketLookupResult{}, false
	}
	return p2p.UDPPacketLookupResult{
		SessionID: session.sessionID,
		Token:     session.token,
	}, true
}

func RecordObservation(routeKey, role string, sample p2p.ProbeSample) {
	if routeKey == "" || role == "" || sample.ProbePort == 0 || sample.ObservedAddr == "" {
		return
	}
	session := getByRoute(routeKey)
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if time.Now().After(session.expiresAt) {
		deleteSession(session)
		return
	}
	if _, ok := session.observations[role]; !ok {
		session.observations[role] = make(map[string]p2p.ProbeSample)
	}
	session.observations[role][observationKey(sample)] = sample
}

func AcceptPacket(routeKey string, timestampMs int64, nonce string) bool {
	session := getByRoute(routeKey)
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if time.Now().After(session.expiresAt) {
		deleteSession(session)
		return false
	}
	if session.replay == nil {
		return true
	}
	return session.replay.Accept(timestampMs, nonce)
}

func GetObservations(sessionID, role string) []p2p.ProbeSample {
	if sessionID == "" || role == "" {
		return nil
	}
	session := getByID(sessionID)
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if time.Now().After(session.expiresAt) {
		deleteSession(session)
		return nil
	}
	byPort, ok := session.observations[role]
	if !ok {
		return nil
	}
	samples := make([]p2p.ProbeSample, 0, len(byPort))
	for _, sample := range byPort {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].ProbePort != samples[j].ProbePort {
			return samples[i].ProbePort < samples[j].ProbePort
		}
		return samples[i].ServerReplyAddr < samples[j].ServerReplyAddr
	})
	return samples
}

func observationKey(sample p2p.ProbeSample) string {
	replyAddr := common.ValidateAddr(sample.ServerReplyAddr)
	if replyAddr == "" {
		replyAddr = common.ValidateAddr(sample.ObservedAddr)
	}
	if replyAddr == "" {
		return fmt.Sprintf("%d", sample.ProbePort)
	}
	return fmt.Sprintf("%d|%s", sample.ProbePort, replyAddr)
}

func getByID(sessionID string) *probeSession {
	if sessionID == "" {
		return nil
	}
	value, ok := probeSessionsByID.Load(sessionID)
	if !ok {
		return nil
	}
	session, ok := value.(*probeSession)
	if !ok || session == nil {
		return nil
	}
	return session
}

func getByRoute(routeKey string) *probeSession {
	if routeKey == "" {
		return nil
	}
	value, ok := probeSessionsByRoute.Load(routeKey)
	if !ok {
		return nil
	}
	session, ok := value.(*probeSession)
	if !ok || session == nil {
		return nil
	}
	return session
}

func deleteSession(session *probeSession) {
	if session == nil {
		return
	}
	if session.routeKey != "" {
		probeSessionsByRoute.Delete(session.routeKey)
	}
	if session.sessionID != "" {
		probeSessionsByID.Delete(session.sessionID)
	}
}

func startCleaner() {
	cleanerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				probeSessionsByID.Range(func(key, value any) bool {
					session, ok := value.(*probeSession)
					if !ok || session == nil {
						probeSessionsByID.Delete(key)
						return true
					}
					session.mu.Lock()
					expired := now.After(session.expiresAt)
					session.mu.Unlock()
					if expired {
						deleteSession(session)
					}
					return true
				})
			}
		}()
	})
}
