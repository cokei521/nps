package p2p

import (
	"fmt"
	"net"
	"strings"
)

const defaultSTUNPort = "3478"

func ParseSTUNServerList(raw string) []string {
	return parseAddressList(raw, defaultSTUNPort)
}

func HasProbeProvider(probe P2PProbeConfig, provider string) bool {
	for _, endpoint := range NormalizeProbeEndpoints(probe) {
		if endpoint.Provider == provider {
			return true
		}
	}
	return false
}

func HasUsableProbeEndpoint(probe P2PProbeConfig) bool {
	for _, endpoint := range NormalizeProbeEndpoints(probe) {
		if isSupportedProbeEndpoint(endpoint) {
			return true
		}
	}
	return false
}

func isSupportedProbeEndpoint(endpoint P2PProbeEndpoint) bool {
	switch {
	case endpoint.Provider == ProbeProviderNPS && endpoint.Mode == ProbeModeUDP && endpoint.Network == ProbeNetworkUDP:
		return true
	case endpoint.Provider == ProbeProviderSTUN && endpoint.Mode == ProbeModeBinding && endpoint.Network == ProbeNetworkUDP:
		return true
	default:
		return false
	}
}

func WithDefaultSTUNEndpoints(probe P2PProbeConfig, servers []string) P2PProbeConfig {
	if len(servers) == 0 || HasProbeProvider(probe, ProbeProviderSTUN) {
		return probe
	}
	out := probe
	out.Endpoints = append([]P2PProbeEndpoint{}, probe.Endpoints...)
	for i, addr := range servers {
		out.Endpoints = append(out.Endpoints, P2PProbeEndpoint{
			ID:       fmt.Sprintf("stun-default-%d", i+1),
			Provider: ProbeProviderSTUN,
			Mode:     ProbeModeBinding,
			Network:  ProbeNetworkUDP,
			Address:  addr,
		})
	}
	return out
}

func parseAddressList(raw, defaultPort string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r', '\t', ' ':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		addr := normalizeServerAddr(field, defaultPort)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func normalizeServerAddr(raw, defaultPort string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if defaultPort == "" {
		defaultPort = defaultSTUNPort
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if host == "" || port == "" {
			return ""
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	if strings.Count(raw, ":") > 1 && !strings.HasPrefix(raw, "[") && !strings.HasSuffix(raw, "]") {
		return net.JoinHostPort(raw, defaultPort)
	}
	return net.JoinHostPort(raw, defaultPort)
}
