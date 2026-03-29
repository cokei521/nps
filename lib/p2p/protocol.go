package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
)

const (
	packetTypeProbe   = "probe"
	packetTypeAck     = "probe_ack"
	packetTypeProbeX  = "probe_extra"
	packetTypePunch   = "punch"
	packetTypeSucc    = "success"
	packetTypeEnd     = "end"
	packetTypeAccept  = "accept"
	packetTypeReady   = "ready"
	udpPayloadVersion = 1
	udpFlagExtraReply = 1 << 0

	ProbeProviderNPS  = "nps"
	ProbeProviderSTUN = "stun"
	ProbeModeUDP      = "udp_probe"
	ProbeModeBinding  = "stun_binding"
	ProbeNetworkUDP   = "udp"

	NATMappingUnknown             = "unknown"
	NATMappingEndpointIndependent = "endpoint_independent"
	NATMappingEndpointDependent   = "endpoint_dependent"
	NATFilteringUnknown           = "unknown"
	NATFilteringOpen              = "open_or_address_restricted"
	NATFilteringPortRestricted    = "port_restricted"
	NATTypeUnknown                = "unknown"
	NATTypeCone                   = "cone"
	NATTypeRestrictedCone         = "restricted_cone"
	NATTypePortRestricted         = "port_restricted"
	NATTypeSymmetric              = "symmetric"
	ClassificationConfidenceLow   = "low"
	ClassificationConfidenceMed   = "medium"
	ClassificationConfidenceHigh  = "high"
)

type ProbeSample struct {
	EndpointID      string `json:"endpoint_id,omitempty"`
	Provider        string `json:"provider,omitempty"`
	Mode            string `json:"mode,omitempty"`
	ProbePort       int    `json:"probe_port"`
	ObservedAddr    string `json:"observed_addr"`
	ServerReplyAddr string `json:"server_reply_addr,omitempty"`
	ExtraReply      bool   `json:"extra_reply,omitempty"`
}

type PortMappingInfo struct {
	Method       string `json:"method,omitempty"`
	ExternalAddr string `json:"external_addr,omitempty"`
	InternalAddr string `json:"internal_addr,omitempty"`
	LeaseSeconds int    `json:"lease_seconds,omitempty"`
}

type NatObservation struct {
	PublicIP             string           `json:"public_ip"`
	ObservedBasePort     int              `json:"observed_base_port"`
	ObservedInterval     int              `json:"observed_interval"`
	ProbePortRestricted  bool             `json:"probe_port_restricted"`
	FilteringTested      bool             `json:"filtering_tested,omitempty"`
	MappingBehavior      string           `json:"mapping_behavior,omitempty"`
	FilteringBehavior    string           `json:"filtering_behavior,omitempty"`
	NATType              string           `json:"nat_type,omitempty"`
	ClassificationLevel  string           `json:"classification_level,omitempty"`
	ProbeIPCount         int              `json:"probe_ip_count,omitempty"`
	ProbeEndpointCount   int              `json:"probe_endpoint_count,omitempty"`
	ConflictingSignals   bool             `json:"conflicting_signals,omitempty"`
	MappingConfidenceLow bool             `json:"mapping_confidence_low"`
	PortMapping          *PortMappingInfo `json:"port_mapping,omitempty"`
	Samples              []ProbeSample    `json:"samples,omitempty"`
}

type P2PTimeouts struct {
	ProbeTimeoutMs     int `json:"probe_timeout_ms"`
	HandshakeTimeoutMs int `json:"handshake_timeout_ms"`
	TransportTimeoutMs int `json:"transport_timeout_ms"`
}

type P2PPeerInfo struct {
	Role          string          `json:"role"`
	Nat           NatObservation  `json:"nat"`
	LocalAddrs    []string        `json:"local_addrs,omitempty"`
	Families      []P2PFamilyInfo `json:"families,omitempty"`
	TransportMode string          `json:"transport_mode,omitempty"`
	TransportData string          `json:"transport_data,omitempty"`
}

type P2PFamilyInfo struct {
	Family     string         `json:"family"`
	Nat        NatObservation `json:"nat"`
	LocalAddrs []string       `json:"local_addrs,omitempty"`
}

type P2PProbeEndpoint struct {
	ID       string            `json:"id,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Mode     string            `json:"mode,omitempty"`
	Network  string            `json:"network,omitempty"`
	Address  string            `json:"address"`
	Options  map[string]string `json:"options,omitempty"`
}

type P2PProbeConfig struct {
	Version          int                `json:"version"`
	Provider         string             `json:"provider"`
	Mode             string             `json:"mode"`
	Network          string             `json:"network"`
	Endpoints        []P2PProbeEndpoint `json:"endpoints"`
	ExpectExtraReply bool               `json:"expect_extra_reply,omitempty"`
	Options          map[string]string  `json:"options,omitempty"`
}

type P2PPunchStart struct {
	SessionID string         `json:"session_id"`
	Token     string         `json:"token"`
	Wire      P2PWireSpec    `json:"wire"`
	Role      string         `json:"role"`
	PeerRole  string         `json:"peer_role"`
	Probe     P2PProbeConfig `json:"probe"`
	Timeouts  P2PTimeouts    `json:"timeouts"`
}

type P2PProbeReport struct {
	SessionID string      `json:"session_id"`
	Token     string      `json:"token"`
	Role      string      `json:"role"`
	PeerRole  string      `json:"peer_role"`
	Self      P2PPeerInfo `json:"self"`
}

type P2PProbeSummary struct {
	SessionID string         `json:"session_id"`
	Token     string         `json:"token"`
	Role      string         `json:"role"`
	PeerRole  string         `json:"peer_role"`
	Self      P2PPeerInfo    `json:"self"`
	Peer      P2PPeerInfo    `json:"peer"`
	Timeouts  P2PTimeouts    `json:"timeouts"`
	Hints     map[string]any `json:"hints,omitempty"`
}

type P2PPunchReady struct {
	SessionID string `json:"session_id"`
	Role      string `json:"role"`
}

type P2PPunchGo struct {
	SessionID string `json:"session_id"`
	Role      string `json:"role"`
	DelayMs   int    `json:"delay_ms"`
	SentAtMs  int64  `json:"sent_at_ms,omitempty"`
}

type P2PPunchProgress struct {
	SessionID  string            `json:"session_id"`
	Role       string            `json:"role"`
	Stage      string            `json:"stage"`
	Status     string            `json:"status,omitempty"`
	Detail     string            `json:"detail,omitempty"`
	LocalAddr  string            `json:"local_addr,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Timestamp  int64             `json:"timestamp,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
	Counters   map[string]int    `json:"counters,omitempty"`
}

type P2PPunchAbort struct {
	SessionID string `json:"session_id"`
	Role      string `json:"role"`
	Reason    string `json:"reason"`
}

type P2PSessionJoin struct {
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
}

type UDPPacket struct {
	WireID          string `json:"-"`
	PayloadMinBytes int    `json:"-"`
	PayloadMaxBytes int    `json:"-"`
	SessionID       string `json:"session_id"`
	Token           string `json:"-"`
	Type            string `json:"type,omitempty"`
	Role            string `json:"role,omitempty"`
	NominationEpoch uint32 `json:"nomination_epoch,omitempty"`
	ProbePort       int    `json:"probe_port,omitempty"`
	ObservedAddr    string `json:"observed_addr,omitempty"`
	ExtraReply      bool   `json:"extra_reply,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Nonce           string `json:"nonce,omitempty"`
}

func newUDPPacket(sessionID, token, role, typ string) *UDPPacket {
	return newUDPPacketWithWire(sessionID, token, role, typ, P2PWireSpec{RouteID: sessionID})
}

func newUDPPacketWithWire(sessionID, token, role, typ string, wire P2PWireSpec) *UDPPacket {
	wire = NormalizeP2PWireSpec(wire, sessionID)
	return &UDPPacket{
		WireID:          wire.RouteID,
		PayloadMinBytes: wire.PayloadMinBytes,
		PayloadMaxBytes: wire.PayloadMaxBytes,
		Type:            typ,
		SessionID:       sessionID,
		Token:           token,
		Role:            role,
		Timestamp:       time.Now().UnixMilli(),
	}
}

func EncodeUDPPacket(pkt *UDPPacket) ([]byte, error) {
	if pkt == nil {
		return nil, fmt.Errorf("nil udp packet")
	}
	if pkt.WireID == "" {
		pkt.WireID = pkt.SessionID
	}
	if pkt.Timestamp == 0 {
		pkt.Timestamp = time.Now().UnixMilli()
	}
	nonce, nonceText, err := udpPacketNonceBytes(pkt.Nonce)
	if err != nil {
		return nil, err
	}
	pkt.Nonce = nonceText
	route, err := udpPacketRouteBytes(pkt.WireID)
	if err != nil {
		return nil, err
	}
	payload, err := encodeUDPPacketPayload(pkt)
	if err != nil {
		return nil, err
	}
	sealed, err := sealUDPPayload(pkt.Token, hex.EncodeToString(route[:]), nonce, payload)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, udpPacketEnvelopeSize+len(sealed))
	copy(raw[:udpPacketRouteSize], route[:])
	copy(raw[udpPacketRouteSize:udpPacketEnvelopeSize], nonce)
	copy(raw[udpPacketEnvelopeSize:], sealed)
	return raw, nil
}

func DecodeUDPPacket(data []byte, token string) (*UDPPacket, error) {
	wire, err := parseUDPPacketWire(data)
	if err != nil {
		return nil, err
	}
	return decodeUDPPacketWire(wire, UDPPacketLookupResult{Token: token})
}

func DecodeUDPPacketWithLookup(data []byte, lookup func(routeKey string) (UDPPacketLookupResult, bool)) (*UDPPacket, error) {
	wire, err := parseUDPPacketWire(data)
	if err != nil {
		return nil, err
	}
	if lookup == nil {
		return nil, ErrP2PTokenMismatch
	}
	route, ok := lookup(wire.RouteKey)
	if !ok || route.Token == "" {
		return nil, ErrP2PTokenMismatch
	}
	return decodeUDPPacketWire(wire, route)
}

func WriteBridgeMessage(c *conn.Conn, flag string, payload any) error {
	if c == nil {
		return fmt.Errorf("nil bridge conn")
	}
	_, err := c.SendInfo(payload, flag)
	return err
}

func WritePunchProgress(c *conn.Conn, progress P2PPunchProgress) error {
	if progress.Timestamp == 0 {
		progress.Timestamp = time.Now().UnixMilli()
	}
	return WriteBridgeMessage(c, common.P2P_PUNCH_PROGRESS, progress)
}

func ReadBridgeJSON[T any](c *conn.Conn, expectedFlag string) (T, error) {
	var zero T
	if c == nil {
		return zero, fmt.Errorf("nil bridge conn")
	}
	flag, err := c.ReadFlag()
	if err != nil {
		return zero, err
	}
	raw, err := c.GetShortLenContent()
	if err != nil {
		return zero, err
	}
	if flag == common.P2P_PUNCH_ABORT {
		var abort P2PPunchAbort
		if err := json.Unmarshal(raw, &abort); err != nil {
			return zero, ErrP2PSessionAbort
		}
		if abort.Reason == "" {
			return zero, ErrP2PSessionAbort
		}
		return zero, fmt.Errorf("%w: %s", ErrP2PSessionAbort, abort.Reason)
	}
	if expectedFlag != "" && flag != expectedFlag {
		return zero, fmt.Errorf("unexpected flag %q", flag)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, err
	}
	return out, nil
}

func DefaultTimeouts() P2PTimeouts {
	return P2PTimeouts{
		ProbeTimeoutMs:     5000,
		HandshakeTimeoutMs: 20000,
		TransportTimeoutMs: 10000,
	}
}

func NewProbeAckPacket(sessionID, token, role string, probePort int, observedAddr string, extraReply bool) *UDPPacket {
	return NewProbeAckPacketWithWire(sessionID, token, role, probePort, observedAddr, extraReply, P2PWireSpec{RouteID: sessionID})
}

func NewProbeAckPacketWithWire(sessionID, token, role string, probePort int, observedAddr string, extraReply bool, wire P2PWireSpec) *UDPPacket {
	packetType := packetTypeAck
	if extraReply {
		packetType = packetTypeProbeX
	}
	packet := newUDPPacketWithWire(sessionID, token, role, packetType, wire)
	packet.ProbePort = probePort
	packet.ObservedAddr = observedAddr
	packet.ExtraReply = extraReply
	return packet
}

func decodeUDPPacketWire(wire udpWirePacket, lookup UDPPacketLookupResult) (*UDPPacket, error) {
	if lookup.Token == "" {
		return nil, ErrP2PTokenMismatch
	}
	plaintext, err := openUDPPayload(lookup.Token, wire.RouteKey, wire.Nonce, wire.Ciphertext)
	if err != nil {
		return nil, ErrP2PTokenMismatch
	}
	packet, err := decodeUDPPacketPayload(plaintext)
	if err != nil {
		return nil, ErrP2PTokenMismatch
	}
	if lookup.SessionID != "" && lookup.SessionID != packet.SessionID {
		return nil, ErrP2PTokenMismatch
	}
	packet.Token = lookup.Token
	packet.WireID = wire.RouteKey
	packet.Nonce = hex.EncodeToString(wire.Nonce)
	return packet, nil
}

func encodeUDPPacketPayload(pkt *UDPPacket) ([]byte, error) {
	if pkt == nil {
		return nil, fmt.Errorf("nil udp packet")
	}
	typeCode, err := udpPacketTypeCode(pkt.Type)
	if err != nil {
		return nil, err
	}
	roleCode, err := udpPacketRoleCode(pkt.Role)
	if err != nil {
		return nil, err
	}
	sessionID := []byte(pkt.SessionID)
	observedAddr := []byte(pkt.ObservedAddr)
	if len(sessionID) == 0 || len(sessionID) > 255 || len(observedAddr) > 255 {
		return nil, fmt.Errorf("invalid udp payload lengths")
	}
	baseLen := 20 + len(sessionID) + len(observedAddr) + 2
	targetLen, err := randomPayloadTarget(baseLen, pkt.PayloadMinBytes, pkt.PayloadMaxBytes)
	if err != nil {
		return nil, err
	}
	padLen := targetLen - baseLen
	if padLen < 0 {
		padLen = 0
	}
	payload := make([]byte, baseLen+padLen)
	payload[0] = udpPayloadVersion
	payload[1] = typeCode
	payload[2] = roleCode
	if pkt.ExtraReply {
		payload[3] = udpFlagExtraReply
	}
	binary.BigEndian.PutUint16(payload[4:6], uint16(pkt.ProbePort))
	binary.BigEndian.PutUint64(payload[6:14], uint64(pkt.Timestamp))
	binary.BigEndian.PutUint32(payload[14:18], pkt.NominationEpoch)
	payload[18] = byte(len(sessionID))
	payload[19] = byte(len(observedAddr))
	offset := 20
	copy(payload[offset:offset+len(sessionID)], sessionID)
	offset += len(sessionID)
	copy(payload[offset:offset+len(observedAddr)], observedAddr)
	offset += len(observedAddr)
	binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(padLen))
	offset += 2
	if padLen > 0 {
		if _, err := rand.Read(payload[offset : offset+padLen]); err != nil {
			return nil, err
		}
	}
	return payload, nil
}

func decodeUDPPacketPayload(payload []byte) (*UDPPacket, error) {
	if len(payload) < 22 || payload[0] != udpPayloadVersion {
		return nil, ErrP2PTokenMismatch
	}
	packetType, err := udpPacketTypeFromCode(payload[1])
	if err != nil {
		return nil, err
	}
	role, err := udpPacketRoleFromCode(payload[2])
	if err != nil {
		return nil, err
	}
	sessionLen := int(payload[18])
	observedLen := int(payload[19])
	offset := 20
	if len(payload) < offset+sessionLen+observedLen+2 {
		return nil, ErrP2PTokenMismatch
	}
	sessionID := string(payload[offset : offset+sessionLen])
	offset += sessionLen
	observedAddr := string(payload[offset : offset+observedLen])
	offset += observedLen
	padLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if len(payload) != offset+padLen || sessionID == "" {
		return nil, ErrP2PTokenMismatch
	}
	return &UDPPacket{
		SessionID:       sessionID,
		Type:            packetType,
		Role:            role,
		NominationEpoch: binary.BigEndian.Uint32(payload[14:18]),
		ProbePort:       int(binary.BigEndian.Uint16(payload[4:6])),
		ObservedAddr:    observedAddr,
		ExtraReply:      payload[3]&udpFlagExtraReply != 0,
		Timestamp:       int64(binary.BigEndian.Uint64(payload[6:14])),
	}, nil
}

func sealUDPPayload(token, routeKey string, nonce, payload []byte) ([]byte, error) {
	aead, aad, err := udpPacketCipher(token, routeKey)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, payload, aad), nil
}

func openUDPPayload(token, routeKey string, nonce, sealed []byte) ([]byte, error) {
	aead, aad, err := udpPacketCipher(token, routeKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, sealed, aad)
}

func udpPacketCipher(token, routeKey string) (cipher.AEAD, []byte, error) {
	if token == "" || routeKey == "" {
		return nil, nil, fmt.Errorf("empty udp packet key material")
	}
	key := sha256.Sum256([]byte("nps-p2p-aead|" + routeKey + "|" + token))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	routeBytes, err := hex.DecodeString(routeKey)
	if err != nil {
		return nil, nil, err
	}
	return aead, routeBytes, nil
}

func udpPacketTypeCode(packetType string) (byte, error) {
	switch packetType {
	case packetTypeProbe:
		return 1, nil
	case packetTypeAck:
		return 2, nil
	case packetTypeProbeX:
		return 3, nil
	case packetTypePunch:
		return 4, nil
	case packetTypeSucc:
		return 5, nil
	case packetTypeEnd:
		return 6, nil
	case packetTypeAccept:
		return 7, nil
	case packetTypeReady:
		return 8, nil
	default:
		return 0, fmt.Errorf("unsupported udp packet type %q", packetType)
	}
}

func udpPacketTypeFromCode(code byte) (string, error) {
	switch code {
	case 1:
		return packetTypeProbe, nil
	case 2:
		return packetTypeAck, nil
	case 3:
		return packetTypeProbeX, nil
	case 4:
		return packetTypePunch, nil
	case 5:
		return packetTypeSucc, nil
	case 6:
		return packetTypeEnd, nil
	case 7:
		return packetTypeAccept, nil
	case 8:
		return packetTypeReady, nil
	default:
		return "", fmt.Errorf("unsupported udp packet type code %d", code)
	}
}

func udpPacketRoleCode(role string) (byte, error) {
	switch role {
	case "":
		return 0, nil
	case common.WORK_P2P_VISITOR:
		return 1, nil
	case common.WORK_P2P_PROVIDER:
		return 2, nil
	default:
		return 0, fmt.Errorf("unsupported udp packet role %q", role)
	}
}

func udpPacketRoleFromCode(code byte) (string, error) {
	switch code {
	case 0:
		return "", nil
	case 1:
		return common.WORK_P2P_VISITOR, nil
	case 2:
		return common.WORK_P2P_PROVIDER, nil
	default:
		return "", fmt.Errorf("unsupported udp packet role code %d", code)
	}
}

func NormalizeProbeEndpoint(probe P2PProbeConfig, endpoint P2PProbeEndpoint) P2PProbeEndpoint {
	if endpoint.Provider == "" {
		endpoint.Provider = probe.Provider
	}
	if endpoint.Mode == "" {
		endpoint.Mode = probe.Mode
	}
	if endpoint.Network == "" {
		endpoint.Network = probe.Network
	}
	return endpoint
}

func NormalizeProbeEndpoints(probe P2PProbeConfig) []P2PProbeEndpoint {
	endpoints := make([]P2PProbeEndpoint, 0, len(probe.Endpoints))
	for _, endpoint := range probe.Endpoints {
		normalized := NormalizeProbeEndpoint(probe, endpoint)
		if normalized.Address == "" {
			continue
		}
		endpoints = append(endpoints, normalized)
	}
	return endpoints
}

func MergeProbeSamples(serverSamples, clientSamples []ProbeSample) []ProbeSample {
	out := make([]ProbeSample, 0, len(serverSamples)+len(clientSamples))
	indexByKey := make(map[string]int, len(serverSamples)+len(clientSamples))
	addOrMerge := func(sample ProbeSample, preferReply bool) {
		normalizeProbeSample(&sample)
		key := probeSampleMergeKey(sample)
		if idx, ok := indexByKey[key]; ok {
			out[idx] = mergeProbeSample(out[idx], sample, preferReply)
			return
		}
		indexByKey[key] = len(out)
		out = append(out, sample)
	}

	for _, sample := range clientSamples {
		addOrMerge(sample, true)
	}
	for _, sample := range serverSamples {
		normalizeProbeSample(&sample)
		if isWildcardNPSProbeSample(sample) {
			mergedAny := false
			for i := range out {
				if canMergeWildcardNPSProbeSample(sample, out[i]) {
					out[i] = mergeProbeSample(out[i], sample, false)
					mergedAny = true
				}
			}
			if mergedAny {
				continue
			}
		}
		addOrMerge(sample, false)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		if out[i].ProbePort != out[j].ProbePort {
			return out[i].ProbePort < out[j].ProbePort
		}
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID < out[j].EndpointID
		}
		if out[i].ObservedAddr != out[j].ObservedAddr {
			return out[i].ObservedAddr < out[j].ObservedAddr
		}
		return out[i].ServerReplyAddr < out[j].ServerReplyAddr
	})
	return out
}

func probeSampleMergeKey(sample ProbeSample) string {
	if sample.Provider == ProbeProviderNPS && sample.ProbePort > 0 {
		if replyIP := probeSampleReplyIP(sample.ServerReplyAddr); replyIP != "" {
			return sample.Provider + "|" + sample.Mode + "|" + strconv.Itoa(sample.ProbePort) + "|" + replyIP
		}
		return sample.Provider + "|" + sample.Mode + "|" + strconv.Itoa(sample.ProbePort)
	}
	if sample.EndpointID != "" {
		return sample.Provider + "|" + sample.Mode + "|" + sample.EndpointID
	}
	return sample.Provider + "|" + sample.Mode + "|" + strconv.Itoa(sample.ProbePort) + "|" + sample.ObservedAddr + "|" + sample.ServerReplyAddr
}

func mergeProbeSample(existing, sample ProbeSample, preferReply bool) ProbeSample {
	if existing.EndpointID == "" {
		existing.EndpointID = sample.EndpointID
	}
	if existing.Provider == "" {
		existing.Provider = sample.Provider
	}
	if existing.Mode == "" {
		existing.Mode = sample.Mode
	}
	if existing.ProbePort == 0 {
		existing.ProbePort = sample.ProbePort
	}
	if existing.ObservedAddr == "" {
		existing.ObservedAddr = sample.ObservedAddr
	}
	if preferReply {
		if sample.ServerReplyAddr != "" {
			existing.ServerReplyAddr = sample.ServerReplyAddr
		}
	} else if existing.ServerReplyAddr == "" {
		existing.ServerReplyAddr = sample.ServerReplyAddr
	}
	existing.ExtraReply = existing.ExtraReply || sample.ExtraReply
	return existing
}

func isWildcardNPSProbeSample(sample ProbeSample) bool {
	return sample.Provider == ProbeProviderNPS && sample.ProbePort > 0 && probeSampleReplyIP(sample.ServerReplyAddr) == ""
}

func canMergeWildcardNPSProbeSample(wildcard, existing ProbeSample) bool {
	return wildcard.Provider == ProbeProviderNPS &&
		existing.Provider == ProbeProviderNPS &&
		wildcard.Mode == existing.Mode &&
		wildcard.ProbePort == existing.ProbePort &&
		wildcard.ProbePort > 0
}

func probeSampleReplyIP(addr string) string {
	ip := common.NormalizeIP(common.ParseIPFromAddr(addr))
	if ip == nil || common.IsZeroIP(ip) || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func normalizeProbeSample(sample *ProbeSample) {
	if sample == nil {
		return
	}
	if sample.Provider == "" {
		sample.Provider = ProbeProviderNPS
	}
	if sample.Mode == "" {
		if sample.Provider == ProbeProviderSTUN {
			sample.Mode = ProbeModeBinding
		} else {
			sample.Mode = ProbeModeUDP
		}
	}
}
