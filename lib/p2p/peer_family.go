package p2p

import (
	"net"
	"strings"

	"github.com/djylb/nps/lib/common"
)

func (f udpAddrFamily) String() string {
	switch f {
	case udpFamilyV4:
		return "udp4"
	case udpFamilyV6:
		return "udp6"
	default:
		return ""
	}
}

func parseUDPAddrFamily(value string) udpAddrFamily {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "udp4", "ipv4", "ip4", "v4":
		return udpFamilyV4
	case "udp6", "ipv6", "ip6", "v6":
		return udpFamilyV6
	default:
		return udpFamilyAny
	}
}

func NormalizePeerFamilyInfos(peer P2PPeerInfo) []P2PFamilyInfo {
	if len(peer.Families) == 0 {
		if family := inferPeerInfoFamily(peer); family != udpFamilyAny {
			return []P2PFamilyInfo{normalizeFamilyInfo(P2PFamilyInfo{
				Family:     family.String(),
				Nat:        peer.Nat,
				LocalAddrs: append([]string(nil), peer.LocalAddrs...),
			})}
		}
		return nil
	}
	infos := make([]P2PFamilyInfo, 0, len(peer.Families))
	seen := make(map[string]struct{}, len(peer.Families))
	for _, info := range peer.Families {
		normalized := normalizeFamilyInfo(info)
		if normalized.Family == "" {
			continue
		}
		if _, ok := seen[normalized.Family]; ok {
			continue
		}
		seen[normalized.Family] = struct{}{}
		infos = append(infos, normalized)
	}
	if len(infos) == 0 {
		if family := inferPeerInfoFamily(peer); family != udpFamilyAny {
			return []P2PFamilyInfo{normalizeFamilyInfo(P2PFamilyInfo{
				Family:     family.String(),
				Nat:        peer.Nat,
				LocalAddrs: append([]string(nil), peer.LocalAddrs...),
			})}
		}
	}
	return infos
}

func BuildPeerInfo(role, transportMode, transportData string, families []P2PFamilyInfo) P2PPeerInfo {
	normalized := make([]P2PFamilyInfo, 0, len(families))
	for _, family := range families {
		family = normalizeFamilyInfo(family)
		if family.Family == "" {
			continue
		}
		normalized = append(normalized, family)
	}
	info := P2PPeerInfo{
		Role:          role,
		TransportMode: transportMode,
		TransportData: transportData,
		Families:      normalized,
	}
	if len(normalized) > 0 {
		primary := selectPrimaryFamilyInfo(normalized)
		info.Nat = primary.Nat
		info.LocalAddrs = mergeFamilyLocalAddrs(normalized)
	}
	return info
}

func PeerInfoForFamily(peer P2PPeerInfo, family udpAddrFamily) (P2PPeerInfo, bool) {
	if family == udpFamilyAny {
		return peer, true
	}
	for _, info := range NormalizePeerFamilyInfos(peer) {
		if parseUDPAddrFamily(info.Family) != family {
			continue
		}
		return BuildPeerInfo(peer.Role, peer.TransportMode, peer.TransportData, []P2PFamilyInfo{info}), true
	}
	return P2PPeerInfo{}, false
}

func FilterProbeSamplesByFamily(samples []ProbeSample, family string) []ProbeSample {
	want := parseUDPAddrFamily(family)
	if want == udpFamilyAny || len(samples) == 0 {
		return append([]ProbeSample(nil), samples...)
	}
	filtered := make([]ProbeSample, 0, len(samples))
	for _, sample := range samples {
		if sampleFamily(sample) != want {
			continue
		}
		filtered = append(filtered, sample)
	}
	return filtered
}

func normalizeFamilyInfo(info P2PFamilyInfo) P2PFamilyInfo {
	family := parseUDPAddrFamily(info.Family)
	if family == udpFamilyAny {
		family = inferFamilyInfo(info)
	}
	info.Family = family.String()
	if info.Family == "" {
		return P2PFamilyInfo{}
	}
	info.LocalAddrs = filterLocalAddrsByFamily(info.LocalAddrs, family)
	info.Nat.Samples = FilterProbeSamplesByFamily(info.Nat.Samples, info.Family)
	if !family.matchesIP(net.ParseIP(info.Nat.PublicIP)) {
		info.Nat.PublicIP = ""
	}
	return info
}

func inferPeerInfoFamily(peer P2PPeerInfo) udpAddrFamily {
	if family := detectIPFamily(net.ParseIP(peer.Nat.PublicIP)); family != udpFamilyAny {
		return family
	}
	for _, sample := range peer.Nat.Samples {
		if family := sampleFamily(sample); family != udpFamilyAny {
			return family
		}
	}
	for _, addr := range peer.LocalAddrs {
		if family := detectAddressFamily(addr); family != udpFamilyAny {
			return family
		}
	}
	return udpFamilyAny
}

func inferFamilyInfo(info P2PFamilyInfo) udpAddrFamily {
	if family := detectIPFamily(net.ParseIP(info.Nat.PublicIP)); family != udpFamilyAny {
		return family
	}
	for _, sample := range info.Nat.Samples {
		if family := sampleFamily(sample); family != udpFamilyAny {
			return family
		}
	}
	for _, addr := range info.LocalAddrs {
		if family := detectAddressFamily(addr); family != udpFamilyAny {
			return family
		}
	}
	return udpFamilyAny
}

func filterLocalAddrsByFamily(addrs []string, family udpAddrFamily) []string {
	if family == udpFamilyAny || len(addrs) == 0 {
		return append([]string(nil), addrs...)
	}
	filtered := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		addr = common.ValidateAddr(addr)
		if addr == "" || !family.matchesAddr(addr) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		filtered = append(filtered, addr)
	}
	return filtered
}

func sampleFamily(sample ProbeSample) udpAddrFamily {
	if family := detectAddressFamily(sample.ObservedAddr); family != udpFamilyAny {
		return family
	}
	if family := detectAddressFamily(sample.ServerReplyAddr); family != udpFamilyAny {
		return family
	}
	return udpFamilyAny
}

func selectPrimaryFamilyInfo(infos []P2PFamilyInfo) P2PFamilyInfo {
	if len(infos) == 0 {
		return P2PFamilyInfo{}
	}
	best := infos[0]
	for _, info := range infos[1:] {
		if familyInfoConservativeScore(info) > familyInfoConservativeScore(best) {
			best = info
			continue
		}
		if familyInfoConservativeScore(info) == familyInfoConservativeScore(best) && len(info.Nat.Samples) > len(best.Nat.Samples) {
			best = info
		}
	}
	return best
}

func familyInfoConservativeScore(info P2PFamilyInfo) int {
	score := 0
	if isHardOrUnknownNat(info.Nat) {
		score += 100
	}
	switch info.Nat.NATType {
	case NATTypeUnknown:
		score += 80
	case NATTypeSymmetric:
		score += 70
	case NATTypePortRestricted:
		score += 60
	case NATTypeRestrictedCone:
		score += 40
	case NATTypeCone:
		score += 20
	}
	if info.Nat.ProbePortRestricted {
		score += 15
	}
	if info.Nat.MappingConfidenceLow {
		score += 10
	}
	switch info.Nat.ClassificationLevel {
	case ClassificationConfidenceLow:
		score += 8
	case ClassificationConfidenceMed:
		score += 4
	}
	return score
}

func mergeFamilyLocalAddrs(infos []P2PFamilyInfo) []string {
	out := make([]string, 0, len(infos)*2)
	seen := make(map[string]struct{}, len(infos)*2)
	for _, info := range infos {
		for _, addr := range info.LocalAddrs {
			addr = common.ValidateAddr(addr)
			if addr == "" {
				continue
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}
