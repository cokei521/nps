package p2p

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const (
	minPunchBindingGap       = 5 * time.Millisecond
	sprayPacketJitterPercent = 25
	sprayBurstJitterPercent  = 20
	sprayPhaseJitterPercent  = 20
	periodicJitterPercent    = 12
	controlJitterPercent     = 20
	nominationJitterPercent  = 15
)

type sessionPacer struct {
	seed [32]byte
}

func newSessionPacer(start P2PPunchStart) *sessionPacer {
	wire := p2pStartWireSpec(start)
	sum := sha256.Sum256([]byte("nps-p2p-pacer|" + start.SessionID + "|" + start.Token + "|" + wire.RouteID + "|" + start.Role))
	return &sessionPacer{seed: sum}
}

func (p *sessionPacer) sprayPacketGap(targetIndex, burstIndex int, base time.Duration) time.Duration {
	return p.duration("spray-packet", targetIndex*1024+burstIndex, base, minPunchBindingGap, sprayPacketJitterPercent)
}

func (p *sessionPacer) sprayBurstGap(targetIndex int, base time.Duration) time.Duration {
	return p.duration("spray-burst", targetIndex, base, minPunchBindingGap, sprayBurstJitterPercent)
}

func (p *sessionPacer) sprayPhaseGap(round int, base time.Duration) time.Duration {
	return p.duration("spray-phase", round, base, minPunchBindingGap, sprayPhaseJitterPercent)
}

func (p *sessionPacer) periodicRetryDelay(attempt int) time.Duration {
	return p.duration("spray-periodic", attempt, basePeriodicSprayDelay(attempt), 500*time.Millisecond, periodicJitterPercent)
}

func (p *sessionPacer) controlGap(packetType string, seq int, base time.Duration) time.Duration {
	return p.duration("control-"+packetType, seq, base, minPunchBindingGap, controlJitterPercent)
}

func (p *sessionPacer) nominationDelay(base time.Duration) time.Duration {
	return p.duration("nomination-delay", 0, base, 0, nominationJitterPercent)
}

func (p *sessionPacer) nominationRetryDelay(epoch uint32, attempt int, base time.Duration) time.Duration {
	return p.duration("nomination-retry", int(epoch)*256+attempt, base, 50*time.Millisecond, nominationJitterPercent)
}

func (p *sessionPacer) duration(label string, index int, base, min time.Duration, jitterPercent int) time.Duration {
	if base <= 0 {
		return 0
	}
	if min > 0 && base < min {
		base = min
	}
	if jitterPercent <= 0 {
		return base
	}
	spread := time.Duration(int64(base) * int64(jitterPercent) / 100)
	if spread <= 0 {
		return base
	}
	offset := p.offset(label, index, spread)
	value := base + offset
	if min > 0 && value < min {
		value = min
	}
	return value
}

func (p *sessionPacer) offset(label string, index int, spread time.Duration) time.Duration {
	if p == nil || spread <= 0 {
		return 0
	}
	sum := sha256.New()
	sum.Write(p.seed[:])
	sum.Write([]byte(label))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(index))
	sum.Write(counter[:])
	buf := sum.Sum(nil)
	value := binary.BigEndian.Uint64(buf[:8])
	window := uint64(spread)*2 + 1
	return time.Duration(value%window) - spread
}

func basePeriodicSprayDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := 1500*time.Millisecond + time.Duration(minInt(attempt, 5))*500*time.Millisecond
	switch attempt % 3 {
	case 1:
		delay += 100 * time.Millisecond
	case 2:
		delay -= 100 * time.Millisecond
	}
	if delay < 500*time.Millisecond {
		delay = 500 * time.Millisecond
	}
	if delay > 4*time.Second {
		delay = 4 * time.Second
	}
	return delay
}
