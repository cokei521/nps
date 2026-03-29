package p2p

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
)

const (
	predictionHistoryTTL        = 30 * time.Minute
	predictionHistoryMaxEntries = 256
	predictionHistoryMaxOffsets = 6
	adaptiveProfileHistoryTTL   = 2 * time.Hour
	adaptiveProfileMaxEntries   = 512
)

type predictionHistoryEntry struct {
	updatedAt time.Time
	offsets   map[int]predictionOffsetStat
}

type predictionOffsetStat struct {
	count     int
	updatedAt time.Time
}

type predictionHistoryStore struct {
	mu      sync.Mutex
	entries map[string]*predictionHistoryEntry
}

var globalPredictionHistory = &predictionHistoryStore{
	entries: make(map[string]*predictionHistoryEntry),
}

type adaptiveProfileEntry struct {
	updatedAt      time.Time
	successCount   int
	timeoutCount   int
	lastSuccessAt  time.Time
	lastTimeoutAt  time.Time
	transportModes map[string]int
}

type adaptiveProfileStore struct {
	mu      sync.Mutex
	entries map[string]*adaptiveProfileEntry
}

var globalAdaptiveProfileHistory = &adaptiveProfileStore{
	entries: make(map[string]*adaptiveProfileEntry),
}

func recordPredictionSuccess(obs NatObservation, remoteAddr string) {
	basePort := obs.ObservedBasePort
	remotePort := common.GetPortByAddr(remoteAddr)
	if basePort <= 0 || remotePort <= 0 {
		return
	}
	key := predictionHistoryKey(obs)
	if key == "" {
		return
	}
	globalPredictionHistory.record(key, remotePort-basePort)
}

func predictionHistoryOffsets(obs NatObservation) []int {
	return globalPredictionHistory.offsets(predictionHistoryKey(obs))
}

func predictionHistoryKey(obs NatObservation) string {
	if obs.PublicIP == "" {
		return ""
	}
	return obs.PublicIP + "|" + obs.NATType + "|" + obs.MappingBehavior + "|" + strconv.Itoa(obs.ObservedInterval)
}

func recordAdaptiveProfileSuccess(summary P2PProbeSummary, transportMode string) {
	key := adaptiveProfileKey(summary)
	if key == "" {
		return
	}
	globalAdaptiveProfileHistory.recordSuccess(key, transportMode)
}

func recordAdaptiveProfileTimeout(summary P2PProbeSummary) {
	key := adaptiveProfileKey(summary)
	if key == "" {
		return
	}
	globalAdaptiveProfileHistory.recordTimeout(key)
}

func adaptiveProfileScore(summary P2PProbeSummary) int {
	return globalAdaptiveProfileHistory.score(adaptiveProfileKey(summary))
}

func adaptiveProfileKey(summary P2PProbeSummary) string {
	family := inferPeerInfoFamily(summary.Self)
	if family == udpFamilyAny {
		if infos := NormalizePeerFamilyInfos(summary.Self); len(infos) > 0 {
			family = parseUDPAddrFamily(infos[0].Family)
		}
	}
	if family == udpFamilyAny {
		family = inferPeerInfoFamily(summary.Peer)
	}
	if family == udpFamilyAny {
		if infos := NormalizePeerFamilyInfos(summary.Peer); len(infos) > 0 {
			family = parseUDPAddrFamily(infos[0].Family)
		}
	}
	if family == udpFamilyAny {
		return ""
	}
	return strings.Join([]string{
		family.String(),
		adaptiveNatFingerprint(summary.Self.Nat),
		adaptiveNatFingerprint(summary.Peer.Nat),
	}, "||")
}

func adaptiveNatFingerprint(obs NatObservation) string {
	flags := make([]string, 0, 4)
	if obs.ProbePortRestricted {
		flags = append(flags, "probe_port_restricted")
	}
	if obs.MappingConfidenceLow {
		flags = append(flags, "mapping_conf_low")
	}
	if obs.FilteringTested {
		flags = append(flags, "filter_tested")
	}
	if obs.PortMapping != nil && obs.PortMapping.Method != "" {
		flags = append(flags, "portmap_"+obs.PortMapping.Method)
	}
	return strings.Join([]string{
		nonEmptyOr(obs.NATType, NATTypeUnknown),
		nonEmptyOr(obs.MappingBehavior, NATMappingUnknown),
		nonEmptyOr(obs.FilteringBehavior, NATFilteringUnknown),
		nonEmptyOr(obs.ClassificationLevel, ClassificationConfidenceLow),
		"providers=" + strconv.Itoa(natProbeProviderCount(obs)),
		"endpoints=" + strconv.Itoa(bucketAdaptiveInt(obs.ProbeEndpointCount)),
		"interval=" + strconv.Itoa(bucketAdaptiveInterval(obs.ObservedInterval)),
		strings.Join(flags, ","),
	}, "|")
}

func bucketAdaptiveInt(value int) int {
	switch {
	case value <= 0:
		return 0
	case value == 1:
		return 1
	case value <= 3:
		return 3
	default:
		return 4
	}
}

func bucketAdaptiveInterval(value int) int {
	switch {
	case value <= 0:
		return 0
	case value == 1:
		return 1
	case value <= 4:
		return 4
	case value <= 16:
		return 16
	default:
		return 32
	}
}

func nonEmptyOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (s *predictionHistoryStore) record(key string, offset int) {
	if key == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry, ok := s.entries[key]
	if !ok {
		entry = &predictionHistoryEntry{offsets: make(map[int]predictionOffsetStat)}
		s.entries[key] = entry
	}
	entry.updatedAt = now
	stat := entry.offsets[offset]
	stat.count++
	stat.updatedAt = now
	entry.offsets[offset] = stat
}

func (s *predictionHistoryStore) offsets(key string) []int {
	if key == "" {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry, ok := s.entries[key]
	if !ok || entry == nil || len(entry.offsets) == 0 {
		return nil
	}
	type scoredOffset struct {
		offset int
		score  int
		count  int
		fresh  time.Time
	}
	items := make([]scoredOffset, 0, len(entry.offsets))
	for offset, stat := range entry.offsets {
		items = append(items, scoredOffset{
			offset: offset,
			score:  predictionOffsetScore(stat, now),
			count:  stat.count,
			fresh:  stat.updatedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		if !items[i].fresh.Equal(items[j].fresh) {
			return items[i].fresh.After(items[j].fresh)
		}
		if absInt(items[i].offset) != absInt(items[j].offset) {
			return absInt(items[i].offset) < absInt(items[j].offset)
		}
		return items[i].offset < items[j].offset
	})
	limit := predictionHistoryMaxOffsets
	if len(items) < limit {
		limit = len(items)
	}
	out := make([]int, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, items[i].offset)
	}
	return out
}

func (s *predictionHistoryStore) pruneLocked(now time.Time) {
	for key, entry := range s.entries {
		if entry == nil {
			delete(s.entries, key)
			continue
		}
		for offset, stat := range entry.offsets {
			if now.Sub(stat.updatedAt) > predictionHistoryTTL {
				delete(entry.offsets, offset)
			}
		}
		if len(entry.offsets) == 0 || now.Sub(entry.updatedAt) > predictionHistoryTTL {
			delete(s.entries, key)
		}
	}
	if len(s.entries) <= predictionHistoryMaxEntries {
		return
	}
	type entryAge struct {
		key       string
		updatedAt time.Time
	}
	ages := make([]entryAge, 0, len(s.entries))
	for key, entry := range s.entries {
		ages = append(ages, entryAge{key: key, updatedAt: entry.updatedAt})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].updatedAt.Before(ages[j].updatedAt) })
	for len(s.entries) > predictionHistoryMaxEntries && len(ages) > 0 {
		delete(s.entries, ages[0].key)
		ages = ages[1:]
	}
}

func (s *adaptiveProfileStore) recordSuccess(key, transportMode string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry := s.ensureEntryLocked(key, now)
	entry.successCount++
	entry.lastSuccessAt = now
	entry.updatedAt = now
	if transportMode != "" {
		if entry.transportModes == nil {
			entry.transportModes = make(map[string]int)
		}
		entry.transportModes[transportMode]++
	}
}

func (s *adaptiveProfileStore) recordTimeout(key string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry := s.ensureEntryLocked(key, now)
	entry.timeoutCount++
	entry.lastTimeoutAt = now
	entry.updatedAt = now
}

func (s *adaptiveProfileStore) score(key string) int {
	if key == "" {
		return 0
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry := s.entries[key]
	if entry == nil {
		return 0
	}
	return adaptiveProfileScoreEntry(entry, now)
}

func (s *adaptiveProfileStore) ensureEntryLocked(key string, now time.Time) *adaptiveProfileEntry {
	entry := s.entries[key]
	if entry != nil {
		return entry
	}
	entry = &adaptiveProfileEntry{updatedAt: now, transportModes: make(map[string]int)}
	s.entries[key] = entry
	return entry
}

func (s *adaptiveProfileStore) pruneLocked(now time.Time) {
	for key, entry := range s.entries {
		if entry == nil || now.Sub(entry.updatedAt) > adaptiveProfileHistoryTTL {
			delete(s.entries, key)
		}
	}
	if len(s.entries) <= adaptiveProfileMaxEntries {
		return
	}
	type entryAge struct {
		key       string
		updatedAt time.Time
	}
	ages := make([]entryAge, 0, len(s.entries))
	for key, entry := range s.entries {
		ages = append(ages, entryAge{key: key, updatedAt: entry.updatedAt})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].updatedAt.Before(ages[j].updatedAt) })
	for len(s.entries) > adaptiveProfileMaxEntries && len(ages) > 0 {
		delete(s.entries, ages[0].key)
		ages = ages[1:]
	}
}

func adaptiveProfileScoreEntry(entry *adaptiveProfileEntry, now time.Time) int {
	if entry == nil {
		return 0
	}
	score := entry.successCount*24 - entry.timeoutCount*16
	switch {
	case !entry.lastSuccessAt.IsZero() && now.Sub(entry.lastSuccessAt) <= 10*time.Minute:
		score += 10
	case !entry.lastSuccessAt.IsZero() && now.Sub(entry.lastSuccessAt) <= adaptiveProfileHistoryTTL/2:
		score += 4
	}
	switch {
	case !entry.lastTimeoutAt.IsZero() && now.Sub(entry.lastTimeoutAt) <= 10*time.Minute:
		score -= 6
	case !entry.lastTimeoutAt.IsZero() && now.Sub(entry.lastTimeoutAt) <= adaptiveProfileHistoryTTL/2:
		score -= 2
	}
	return score
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func predictionOffsetScore(stat predictionOffsetStat, now time.Time) int {
	score := stat.count * 16
	age := now.Sub(stat.updatedAt)
	switch {
	case age <= 2*time.Minute:
		score += 8
	case age <= 10*time.Minute:
		score += 4
	case age <= predictionHistoryTTL/2:
		score += 2
	}
	return score
}
