package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/djylb/nps/lib/common"
	pionstun "github.com/pion/stun/v3"
)

const (
	defaultSTUNCalibrationTimeout = 250 * time.Millisecond
	maxSTUNCalibrationBudget      = 900 * time.Millisecond
	minSTUNCalibrationTimeout     = 120 * time.Millisecond
	maxDerivedSTUNEndpoints       = 2
)

type stunResponseInfo struct {
	observedAddr   string
	responseOrigin string
	otherAddress   string
}

func runSTUNCalibration(ctx context.Context, localConn net.PacketConn, endpoints []P2PProbeEndpoint, probeTimeoutMs int) (ProbeSample, error) {
	samples, err := runSTUNProbes(ctx, localConn, endpoints, probeTimeoutMs)
	if err != nil {
		return ProbeSample{}, err
	}
	if len(samples) == 0 {
		return ProbeSample{}, fmt.Errorf("stun calibration timeout")
	}
	return samples[0], nil
}

func runSTUNProbes(ctx context.Context, localConn net.PacketConn, endpoints []P2PProbeEndpoint, probeTimeoutMs int) ([]ProbeSample, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no stun endpoints")
	}
	budget := maxSTUNCalibrationBudget
	if probeTimeoutMs > 0 {
		derived := time.Duration(probeTimeoutMs) * time.Millisecond / 3
		if derived < budget {
			budget = derived
		}
	}
	if budget < minSTUNCalibrationTimeout {
		budget = minSTUNCalibrationTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, mapP2PContextError(ctx.Err())
		}
		if remaining < budget {
			budget = remaining
		}
	}
	calibrationCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	deadline, _ := calibrationCtx.Deadline()
	samples := make([]ProbeSample, 0, len(endpoints))
	queue := append([]P2PProbeEndpoint(nil), endpoints...)
	seenEndpoints := make(map[string]struct{}, len(queue))
	for _, endpoint := range queue {
		seenEndpoints[endpoint.Address] = struct{}{}
	}
	derivedCount := 0
	lastErr := fmt.Errorf("stun calibration timeout")
	for len(queue) > 0 {
		endpoint := queue[0]
		queue = queue[1:]
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timeout := defaultSTUNCalibrationTimeout
		if value, ok := parseProbeIntOption(endpoint.Options, "timeout_ms"); ok && value > 0 {
			timeout = time.Duration(value) * time.Millisecond
		}
		if timeout < minSTUNCalibrationTimeout {
			timeout = minSTUNCalibrationTimeout
		}
		if remaining < timeout {
			timeout = remaining
		}
		sample, derived, err := runSTUNProbeEndpointDetailed(calibrationCtx, localConn, endpoint, timeout)
		if err == nil {
			samples = append(samples, sample)
			if derived != nil && derived.Address != "" && derivedCount < maxDerivedSTUNEndpoints {
				if _, ok := seenEndpoints[derived.Address]; !ok {
					seenEndpoints[derived.Address] = struct{}{}
					queue = append(queue, *derived)
					derivedCount++
				}
			}
			continue
		}
		lastErr = err
	}
	if len(samples) > 0 {
		return samples, nil
	}
	return nil, lastErr
}

func runSTUNProbeEndpoint(ctx context.Context, localConn net.PacketConn, endpoint P2PProbeEndpoint, timeout time.Duration) (ProbeSample, error) {
	sample, _, err := runSTUNProbeEndpointDetailed(ctx, localConn, endpoint, timeout)
	return sample, err
}

func runSTUNProbeEndpointDetailed(ctx context.Context, localConn net.PacketConn, endpoint P2PProbeEndpoint, timeout time.Duration) (ProbeSample, *P2PProbeEndpoint, error) {
	if localConn == nil {
		return ProbeSample{}, nil, fmt.Errorf("nil local conn")
	}
	if timeout <= 0 {
		timeout = defaultSTUNCalibrationTimeout
	}
	serverAddr, err := resolveUDPAddrContext(ctx, localConn.LocalAddr(), endpoint.Address, timeout)
	if err != nil {
		return ProbeSample{}, nil, err
	}
	request, err := pionstun.Build(pionstun.TransactionID, pionstun.BindingRequest, pionstun.Fingerprint)
	if err != nil {
		return ProbeSample{}, nil, err
	}
	buf := make([]byte, 2048)
	select {
	case <-ctx.Done():
		return ProbeSample{}, nil, mapP2PContextError(ctx.Err())
	default:
	}
	if _, err := localConn.WriteTo(request.Raw, serverAddr); err != nil {
		return ProbeSample{}, nil, err
	}
	deadline := time.Now().Add(timeout)
	_ = localConn.SetReadDeadline(deadline)
	defer func() { _ = localConn.SetReadDeadline(time.Time{}) }()
	for time.Now().Before(deadline) {
		n, replyAddr, err := localConn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			if isIgnorableUDPIcmpError(err) {
				continue
			}
			return ProbeSample{}, nil, err
		}
		info, err := decodeSTUNBindingResponse(buf[:n], request.TransactionID)
		if err != nil {
			continue
		}
		serverReplyAddr := replyAddr.String()
		if info.responseOrigin != "" {
			serverReplyAddr = info.responseOrigin
		}
		var derived *P2PProbeEndpoint
		if info.otherAddress != "" && compatibleSTUNDerivedEndpoint(localConn.LocalAddr(), info.otherAddress, serverReplyAddr) {
			derived = &P2PProbeEndpoint{
				ID:       endpoint.ID + "-other",
				Provider: ProbeProviderSTUN,
				Mode:     ProbeModeBinding,
				Network:  ProbeNetworkUDP,
				Address:  info.otherAddress,
				Options:  endpoint.Options,
			}
		}
		return ProbeSample{
			EndpointID:      endpoint.ID,
			Provider:        ProbeProviderSTUN,
			Mode:            ProbeModeBinding,
			ProbePort:       common.GetPortByAddr(endpoint.Address),
			ObservedAddr:    info.observedAddr,
			ServerReplyAddr: serverReplyAddr,
		}, derived, nil
	}
	return ProbeSample{}, nil, fmt.Errorf("stun probe timeout")
}

func resolveUDPAddrContext(ctx context.Context, localAddr net.Addr, address string, timeout time.Duration) (*net.UDPAddr, error) {
	resolveCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		resolveCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if familyMismatch(localAddr, ip) {
			return nil, fmt.Errorf("resolved ip family mismatch for %s", address)
		}
		return &net.UDPAddr{IP: ip, Port: portNum}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil, err
	}
	var fallback net.IP
	for _, addr := range addrs {
		if ip := common.NormalizeIP(addr.IP); ip != nil {
			if familyMismatch(localAddr, ip) {
				if fallback == nil {
					fallback = ip
				}
				continue
			}
			return &net.UDPAddr{IP: ip, Port: portNum}, nil
		}
	}
	if fallback != nil {
		return nil, fmt.Errorf("resolved only incompatible ip family for %s", address)
	}
	return nil, fmt.Errorf("stun resolve returned no ip for %s", address)
}

func familyMismatch(localAddr net.Addr, ip net.IP) bool {
	return !detectAddrFamily(localAddr).matchesIP(ip)
}

func decodeSTUNBindingResponse(data []byte, txID [pionstun.TransactionIDSize]byte) (stunResponseInfo, error) {
	if !pionstun.IsMessage(data) {
		return stunResponseInfo{}, fmt.Errorf("not a stun packet")
	}
	message := new(pionstun.Message)
	if err := message.UnmarshalBinary(data); err != nil {
		return stunResponseInfo{}, err
	}
	if message.TransactionID != txID {
		return stunResponseInfo{}, fmt.Errorf("transaction mismatch")
	}
	if message.Type != pionstun.BindingSuccess {
		return stunResponseInfo{}, fmt.Errorf("unexpected stun response type %s", message.Type)
	}
	if message.Contains(pionstun.AttrFingerprint) {
		if err := pionstun.Fingerprint.Check(message); err != nil {
			return stunResponseInfo{}, err
		}
	}
	info := stunResponseInfo{}
	var xorAddr pionstun.XORMappedAddress
	if err := xorAddr.GetFrom(message); err == nil {
		info.observedAddr = xorAddr.String()
	} else {
		var mappedAddr pionstun.MappedAddress
		if err := mappedAddr.GetFrom(message); err == nil {
			info.observedAddr = mappedAddr.String()
		}
	}
	if info.observedAddr == "" {
		return stunResponseInfo{}, fmt.Errorf("missing mapped address")
	}
	var responseOrigin pionstun.ResponseOrigin
	if err := responseOrigin.GetFrom(message); err == nil {
		info.responseOrigin = responseOrigin.String()
	}
	var otherAddr pionstun.OtherAddress
	if err := otherAddr.GetFrom(message); err == nil {
		info.otherAddress = otherAddr.String()
	}
	return info, nil
}

func compatibleSTUNDerivedEndpoint(localAddr net.Addr, candidateAddr, responseOrigin string) bool {
	candidateIP := common.ParseIPFromAddr(candidateAddr)
	if candidateIP == nil {
		return false
	}
	if localIP := common.ParseIPFromAddr(addrString(localAddr)); localIP != nil && (localIP.To4() == nil) != (candidateIP.To4() == nil) {
		return false
	}
	if responseOrigin != "" && common.ValidateAddr(candidateAddr) == common.ValidateAddr(responseOrigin) {
		return false
	}
	return true
}
