package p2p

import (
	"sort"
	"sync"
	"time"
)

const defaultReplayWindow = 30 * time.Second
const defaultReplayWindowMaxEntries = 512

type ReplayWindow struct {
	mu         sync.Mutex
	maxAge     time.Duration
	maxEntries int
	observed   map[string]int64
}

func NewReplayWindow(maxAge time.Duration) *ReplayWindow {
	return newReplayWindow(maxAge, defaultReplayWindowMaxEntries)
}

func newReplayWindow(maxAge time.Duration, maxEntries int) *ReplayWindow {
	if maxAge <= 0 {
		maxAge = defaultReplayWindow
	}
	if maxEntries <= 0 {
		maxEntries = defaultReplayWindowMaxEntries
	}
	return &ReplayWindow{
		maxAge:     maxAge,
		maxEntries: maxEntries,
		observed:   make(map[string]int64),
	}
}

func (w *ReplayWindow) Accept(timestampMs int64, nonce string) bool {
	if w == nil {
		return true
	}
	if nonce == "" || timestampMs <= 0 {
		return false
	}
	now := time.Now().UnixMilli()
	windowMs := w.maxAge.Milliseconds()
	if timestampMs < now-windowMs || timestampMs > now+windowMs {
		return false
	}
	expireBefore := now - windowMs
	w.mu.Lock()
	defer w.mu.Unlock()
	for seenNonce, seenTs := range w.observed {
		if seenTs < expireBefore {
			delete(w.observed, seenNonce)
		}
	}
	w.pruneOverflowLocked()
	if _, ok := w.observed[nonce]; ok {
		return false
	}
	w.observed[nonce] = timestampMs
	return true
}

func (w *ReplayWindow) pruneOverflowLocked() {
	if w == nil || w.maxEntries <= 0 || len(w.observed) < w.maxEntries {
		return
	}
	overflow := len(w.observed) - w.maxEntries + 1
	type replaySeen struct {
		nonce string
		ts    int64
	}
	oldest := make([]replaySeen, 0, len(w.observed))
	for nonce, ts := range w.observed {
		oldest = append(oldest, replaySeen{nonce: nonce, ts: ts})
	}
	sort.Slice(oldest, func(i, j int) bool {
		if oldest[i].ts != oldest[j].ts {
			return oldest[i].ts < oldest[j].ts
		}
		return oldest[i].nonce < oldest[j].nonce
	})
	for i := 0; i < overflow && i < len(oldest); i++ {
		delete(w.observed, oldest[i].nonce)
	}
}
