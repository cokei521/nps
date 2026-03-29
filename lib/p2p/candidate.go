package p2p

import (
	"sync"
	"time"
)

type CandidateState string

const (
	CandidateDiscovered CandidateState = "discovered"
	CandidateSucceeded  CandidateState = "succeeded"
	CandidateNominated  CandidateState = "nominated"
	CandidateConfirmed  CandidateState = "confirmed"
	CandidateClosed     CandidateState = "closed"
)

type CandidatePair struct {
	LocalAddr               string         `json:"local_addr"`
	RemoteAddr              string         `json:"remote_addr"`
	State                   CandidateState `json:"state"`
	FirstSeenAt             time.Time      `json:"first_seen_at"`
	LastSeenAt              time.Time      `json:"last_seen_at"`
	SucceededAt             time.Time      `json:"succeeded_at,omitempty"`
	Nominated               bool           `json:"nominated"`
	Confirmed               bool           `json:"confirmed"`
	SuccessCount            int            `json:"success_count,omitempty"`
	Score                   int            `json:"score,omitempty"`
	ScoreReason             string         `json:"score_reason,omitempty"`
	NominationFailures      int            `json:"nomination_failures,omitempty"`
	NominationCooldownUntil time.Time      `json:"nomination_cooldown_until,omitempty"`
}

type CandidateManager struct {
	mu              sync.Mutex
	candidates      map[string]*CandidatePair
	nominatedKey    string
	confirmedKey    string
	candidateRemote string
	confirmedRemote string
}

func NewCandidateManager(rendezvousRemote string) *CandidateManager {
	return &CandidateManager{
		candidates:      make(map[string]*CandidatePair),
		candidateRemote: rendezvousRemote,
	}
}

func (m *CandidateManager) Observe(localAddr, remoteAddr string) *CandidatePair {
	return m.observe(localAddr, remoteAddr, CandidatePriority{})
}

func (m *CandidateManager) observe(localAddr, remoteAddr string, priority CandidatePriority) *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	if pair, ok := m.candidates[key]; ok {
		if pair.State == CandidateClosed && m.confirmedKey == "" {
			pair.State = CandidateDiscovered
			pair.Nominated = false
			pair.Confirmed = false
			pair.SucceededAt = time.Time{}
			pair.SuccessCount = 0
			pair.Score = 0
			pair.ScoreReason = ""
		}
		pair.LastSeenAt = time.Now()
		applyCandidatePriority(pair, priority)
		return cloneCandidatePair(pair)
	}
	now := time.Now()
	pair := &CandidatePair{
		LocalAddr:   localAddr,
		RemoteAddr:  remoteAddr,
		State:       CandidateDiscovered,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	applyCandidatePriority(pair, priority)
	m.candidates[key] = pair
	if m.confirmedRemote == "" || m.confirmedRemote == remoteAddr {
		m.candidateRemote = remoteAddr
	}
	return cloneCandidatePair(pair)
}

func (m *CandidateManager) MarkSucceeded(localAddr, remoteAddr string) *CandidatePair {
	return m.MarkSucceededWithPriority(localAddr, remoteAddr, CandidatePriority{})
}

func (m *CandidateManager) MarkSucceededWithPriority(localAddr, remoteAddr string, priority CandidatePriority) *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	pair, ok := m.candidates[key]
	if !ok {
		now := time.Now()
		pair = &CandidatePair{
			LocalAddr:   localAddr,
			RemoteAddr:  remoteAddr,
			State:       CandidateDiscovered,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
		m.candidates[key] = pair
	}
	now := time.Now()
	pair.LastSeenAt = now
	applyCandidatePriority(pair, priority)
	if pair.State == CandidateClosed {
		if m.confirmedKey == "" {
			pair.Nominated = false
			pair.Confirmed = false
			pair.State = CandidateSucceeded
			pair.SucceededAt = now
			pair.SuccessCount = 0
			pair.SuccessCount++
			if m.confirmedRemote == "" || m.confirmedRemote == remoteAddr {
				m.candidateRemote = remoteAddr
			}
		}
		return cloneCandidatePair(pair)
	}
	pair.State = CandidateSucceeded
	if pair.SucceededAt.IsZero() {
		pair.SucceededAt = now
	}
	pair.SuccessCount++
	if m.confirmedRemote == "" || m.confirmedRemote == remoteAddr {
		m.candidateRemote = remoteAddr
	}
	return cloneCandidatePair(pair)
}

func (m *CandidateManager) TryNominate(localAddr, remoteAddr string) (*CandidatePair, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	pair, ok := m.candidates[key]
	if !ok {
		return nil, false
	}
	pair.LastSeenAt = time.Now()
	if m.nominatedKey != "" {
		return cloneCandidatePair(pair), false
	}
	m.nominatedKey = key
	pair.State = CandidateNominated
	pair.Nominated = true
	if m.confirmedRemote == "" || m.confirmedRemote == remoteAddr {
		m.candidateRemote = remoteAddr
	}
	return cloneCandidatePair(pair), true
}

func (m *CandidateManager) AdoptNomination(localAddr, remoteAddr string) (*CandidatePair, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	pair, ok := m.candidates[key]
	if !ok {
		now := time.Now()
		pair = &CandidatePair{
			LocalAddr:   localAddr,
			RemoteAddr:  remoteAddr,
			State:       CandidateDiscovered,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
		m.candidates[key] = pair
	}
	pair.LastSeenAt = time.Now()
	if m.confirmedKey != "" && m.confirmedKey != key {
		return cloneCandidatePair(pair), false
	}
	if m.nominatedKey == key {
		pair.State = CandidateNominated
		pair.Nominated = true
		return cloneCandidatePair(pair), true
	}
	if m.nominatedKey != "" {
		if previous := m.candidates[m.nominatedKey]; previous != nil {
			revertNominatedPair(previous)
		}
	}
	m.nominatedKey = key
	pair.State = CandidateNominated
	pair.Nominated = true
	if m.confirmedRemote == "" || m.confirmedRemote == remoteAddr {
		m.candidateRemote = remoteAddr
	}
	return cloneCandidatePair(pair), true
}

func (m *CandidateManager) TryNominateBest() (*CandidatePair, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nominatedKey != "" {
		return cloneCandidatePair(m.candidates[m.nominatedKey]), false
	}
	now := time.Now()
	bestKey := ""
	var bestPair *CandidatePair
	for key, pair := range m.candidates {
		if pair == nil || pair.Confirmed || pair.State == CandidateClosed {
			continue
		}
		if pair.State != CandidateSucceeded || pair.SuccessCount == 0 {
			continue
		}
		if !pair.NominationCooldownUntil.IsZero() && pair.NominationCooldownUntil.After(now) {
			continue
		}
		if betterCandidateForNomination(pair, bestPair) {
			bestKey = key
			bestPair = pair
		}
	}
	if bestPair == nil {
		return nil, false
	}
	bestPair.LastSeenAt = time.Now()
	bestPair.State = CandidateNominated
	bestPair.Nominated = true
	m.nominatedKey = bestKey
	if m.confirmedRemote == "" || m.confirmedRemote == bestPair.RemoteAddr {
		m.candidateRemote = bestPair.RemoteAddr
	}
	return cloneCandidatePair(bestPair), true
}

func (m *CandidateManager) Confirm(localAddr, remoteAddr string) *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	pair, ok := m.candidates[key]
	if !ok {
		return nil
	}
	if m.nominatedKey == "" || m.nominatedKey != key {
		return nil
	}
	if m.confirmedKey != "" && m.confirmedKey != key {
		return nil
	}
	pair.LastSeenAt = time.Now()
	pair.State = CandidateConfirmed
	pair.Nominated = true
	pair.Confirmed = true
	m.confirmedKey = key
	m.nominatedKey = key
	m.confirmedRemote = remoteAddr
	m.candidateRemote = remoteAddr
	for otherKey, otherPair := range m.candidates {
		if otherKey == key || otherPair == nil || otherPair.Confirmed {
			continue
		}
		otherPair.State = CandidateClosed
	}
	return cloneCandidatePair(pair)
}

func (m *CandidateManager) BackoffNomination(localAddr, remoteAddr string, cooldown time.Duration) *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	if m.nominatedKey == "" || m.nominatedKey != key || m.confirmedKey != "" {
		return nil
	}
	pair, ok := m.candidates[key]
	if !ok {
		m.nominatedKey = ""
		return nil
	}
	pair.LastSeenAt = time.Now()
	pair.Nominated = false
	pair.NominationFailures++
	if cooldown > 0 {
		pair.NominationCooldownUntil = time.Now().Add(cooldown)
	}
	if pair.SuccessCount > 0 {
		pair.State = CandidateSucceeded
	} else {
		pair.State = CandidateDiscovered
	}
	m.nominatedKey = ""
	return cloneCandidatePair(pair)
}

func (m *CandidateManager) ReleaseNomination(localAddr, remoteAddr string) *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := candidateKey(localAddr, remoteAddr)
	if m.nominatedKey == "" || m.nominatedKey != key || m.confirmedKey != "" {
		return nil
	}
	pair, ok := m.candidates[key]
	if !ok {
		m.nominatedKey = ""
		return nil
	}
	pair.LastSeenAt = time.Now()
	revertNominatedPair(pair)
	m.nominatedKey = ""
	return cloneCandidatePair(pair)
}

func (m *CandidateManager) PruneStale(maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	pruned := 0
	for _, pair := range m.candidates {
		if pair == nil || pair.Confirmed || pair.Nominated || pair.State == CandidateClosed {
			continue
		}
		lastSeen := pair.LastSeenAt
		if lastSeen.IsZero() {
			lastSeen = pair.FirstSeenAt
		}
		if lastSeen.IsZero() || now.Sub(lastSeen) <= maxAge {
			continue
		}
		pair.State = CandidateClosed
		pair.LastSeenAt = now
		pruned++
	}
	return pruned
}

func (m *CandidateManager) CleanupClosed(maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for key, pair := range m.candidates {
		if pair == nil {
			delete(m.candidates, key)
			removed++
			continue
		}
		if pair.State != CandidateClosed || pair.Confirmed {
			continue
		}
		lastSeen := pair.LastSeenAt
		if lastSeen.IsZero() {
			lastSeen = pair.FirstSeenAt
		}
		if lastSeen.IsZero() || now.Sub(lastSeen) <= maxAge {
			continue
		}
		delete(m.candidates, key)
		removed++
	}
	return removed
}

func (m *CandidateManager) ConfirmedRemote() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.confirmedRemote
}

func (m *CandidateManager) CandidateRemote() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.candidateRemote
}

func (m *CandidateManager) NominatedPair() *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nominatedKey == "" {
		return nil
	}
	return cloneCandidatePair(m.candidates[m.nominatedKey])
}

func (m *CandidateManager) ConfirmedPair() *CandidatePair {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.confirmedKey == "" {
		return nil
	}
	return cloneCandidatePair(m.candidates[m.confirmedKey])
}

func (m *CandidateManager) StateCounts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]int{
		"total":      0,
		"active":     0,
		"discovered": 0,
		"succeeded":  0,
		"nominated":  0,
		"confirmed":  0,
		"closed":     0,
	}
	for _, pair := range m.candidates {
		if pair == nil {
			continue
		}
		counts["total"]++
		switch pair.State {
		case CandidateDiscovered:
			counts["discovered"]++
			counts["active"]++
		case CandidateSucceeded:
			counts["succeeded"]++
			counts["active"]++
		case CandidateNominated:
			counts["nominated"]++
			counts["active"]++
		case CandidateConfirmed:
			counts["confirmed"]++
			counts["active"]++
		case CandidateClosed:
			counts["closed"]++
		}
	}
	return counts
}

func candidateKey(localAddr, remoteAddr string) string {
	return localAddr + "->" + remoteAddr
}

func applyCandidatePriority(pair *CandidatePair, priority CandidatePriority) {
	if pair == nil {
		return
	}
	if priority.Score > pair.Score {
		pair.Score = priority.Score
		pair.ScoreReason = priority.Reason
		return
	}
	if priority.Score == pair.Score && pair.ScoreReason == "" {
		pair.ScoreReason = priority.Reason
	}
}

func revertNominatedPair(pair *CandidatePair) {
	if pair == nil {
		return
	}
	pair.Nominated = false
	if pair.SuccessCount > 0 {
		pair.State = CandidateSucceeded
	} else {
		pair.State = CandidateDiscovered
	}
}

func betterCandidateForNomination(pair, best *CandidatePair) bool {
	if pair == nil {
		return false
	}
	if best == nil {
		return true
	}
	if pair.Score != best.Score {
		return pair.Score > best.Score
	}
	if pair.SuccessCount != best.SuccessCount {
		return pair.SuccessCount > best.SuccessCount
	}
	if pair.NominationFailures != best.NominationFailures {
		return pair.NominationFailures < best.NominationFailures
	}
	if !pair.SucceededAt.Equal(best.SucceededAt) {
		if pair.SucceededAt.IsZero() {
			return false
		}
		if best.SucceededAt.IsZero() {
			return true
		}
		return pair.SucceededAt.Before(best.SucceededAt)
	}
	if !pair.FirstSeenAt.Equal(best.FirstSeenAt) {
		return pair.FirstSeenAt.Before(best.FirstSeenAt)
	}
	if pair.LocalAddr != best.LocalAddr {
		return pair.LocalAddr < best.LocalAddr
	}
	return pair.RemoteAddr < best.RemoteAddr
}

func cloneCandidatePair(pair *CandidatePair) *CandidatePair {
	if pair == nil {
		return nil
	}
	cloned := *pair
	return &cloned
}
