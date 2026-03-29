package p2p

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	udpPacketRouteSize         = 16
	udpPacketNonceSize         = 12
	udpPacketEnvelopeSize      = udpPacketRouteSize + udpPacketNonceSize
	udpPacketMinCiphertextSize = 16
	defaultWirePayloadMinBytes = 96
	defaultWirePayloadMaxBytes = 192
)

type P2PWireSpec struct {
	RouteID         string `json:"route_id"`
	PayloadMinBytes int    `json:"payload_min_bytes,omitempty"`
	PayloadMaxBytes int    `json:"payload_max_bytes,omitempty"`
}

type UDPPacketLookupResult struct {
	SessionID string
	Token     string
}

type udpWirePacket struct {
	RouteKey   string
	Nonce      []byte
	Ciphertext []byte
}

func NewP2PWireSpec() (P2PWireSpec, error) {
	routeID, err := newWireRouteID(udpPacketRouteSize)
	if err != nil {
		return P2PWireSpec{}, err
	}
	return NormalizeP2PWireSpec(P2PWireSpec{RouteID: routeID}, ""), nil
}

func NormalizeP2PWireSpec(spec P2PWireSpec, fallbackRouteID string) P2PWireSpec {
	if strings.TrimSpace(spec.RouteID) == "" {
		spec.RouteID = fallbackRouteID
	}
	if spec.PayloadMinBytes <= 0 {
		spec.PayloadMinBytes = defaultWirePayloadMinBytes
	}
	if spec.PayloadMaxBytes <= 0 {
		spec.PayloadMaxBytes = defaultWirePayloadMaxBytes
	}
	if spec.PayloadMinBytes < 32 {
		spec.PayloadMinBytes = 32
	}
	if spec.PayloadMaxBytes < spec.PayloadMinBytes {
		spec.PayloadMaxBytes = spec.PayloadMinBytes
	}
	if spec.PayloadMaxBytes > 1024 {
		spec.PayloadMaxBytes = 1024
	}
	return spec
}

func NormalizeP2PPunchStart(start P2PPunchStart) P2PPunchStart {
	start.Wire = NormalizeP2PWireSpec(start.Wire, start.SessionID)
	return start
}

func WireRouteKey(routeID string) string {
	routeBytes, err := udpPacketRouteBytes(routeID)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(routeBytes[:])
}

func SameWireRoute(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return strings.TrimSpace(left) == strings.TrimSpace(right)
	}
	return WireRouteKey(left) == WireRouteKey(right)
}

func p2pStartWireSpec(start P2PPunchStart) P2PWireSpec {
	return NormalizeP2PWireSpec(start.Wire, start.SessionID)
}

func parseUDPPacketWire(data []byte) (udpWirePacket, error) {
	var wire udpWirePacket
	if len(data) < udpPacketEnvelopeSize+udpPacketMinCiphertextSize {
		return wire, ErrP2PTokenMismatch
	}
	routeBytes := append([]byte(nil), data[:udpPacketRouteSize]...)
	nonce := append([]byte(nil), data[udpPacketRouteSize:udpPacketEnvelopeSize]...)
	ciphertext := append([]byte(nil), data[udpPacketEnvelopeSize:]...)
	if len(ciphertext) < udpPacketMinCiphertextSize {
		return wire, ErrP2PTokenMismatch
	}
	return udpWirePacket{
		RouteKey:   hex.EncodeToString(routeBytes),
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func newWireRouteID(size int) (string, error) {
	if size <= 0 {
		size = udpPacketRouteSize
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func udpPacketRouteBytes(routeID string) ([udpPacketRouteSize]byte, error) {
	var route [udpPacketRouteSize]byte
	routeID = strings.TrimSpace(routeID)
	if routeID == "" {
		return route, fmt.Errorf("empty wire route id")
	}
	if decoded, ok := decodeWireRouteID(routeID); ok {
		copy(route[:], decoded)
		return route, nil
	}
	sum := sha256.Sum256([]byte("nps-p2p-route|" + routeID))
	copy(route[:], sum[:udpPacketRouteSize])
	return route, nil
}

func decodeWireRouteID(routeID string) ([]byte, bool) {
	if decoded, err := base64.RawURLEncoding.DecodeString(routeID); err == nil && len(decoded) == udpPacketRouteSize {
		return decoded, true
	}
	if decoded, err := hex.DecodeString(routeID); err == nil && len(decoded) == udpPacketRouteSize {
		return decoded, true
	}
	return nil, false
}

func udpPacketNonceBytes(nonce string) ([]byte, string, error) {
	nonce = strings.TrimSpace(nonce)
	if nonce != "" {
		if decoded, err := hex.DecodeString(nonce); err == nil && len(decoded) == udpPacketNonceSize {
			return decoded, strings.ToLower(nonce), nil
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(nonce); err == nil && len(decoded) == udpPacketNonceSize {
			return decoded, hex.EncodeToString(decoded), nil
		}
	}
	buf := make([]byte, udpPacketNonceSize)
	if _, err := rand.Read(buf); err != nil {
		return nil, "", err
	}
	return buf, hex.EncodeToString(buf), nil
}

func randomInt(min, max int) (int, error) {
	if max <= min {
		return min, nil
	}
	span := max - min + 1
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		return 0, err
	}
	return min + int(uint16(buf[0])<<8|uint16(buf[1]))%span, nil
}

func randomPayloadTarget(baseLen, minBytes, maxBytes int) (int, error) {
	if baseLen < 0 {
		baseLen = 0
	}
	if minBytes <= 0 {
		minBytes = defaultWirePayloadMinBytes
	}
	if maxBytes <= 0 {
		maxBytes = defaultWirePayloadMaxBytes
	}
	if maxBytes < minBytes {
		maxBytes = minBytes
	}
	minTarget := baseLen
	if minBytes > minTarget {
		minTarget = minBytes
	}
	maxTarget := baseLen
	if maxBytes > maxTarget {
		maxTarget = maxBytes
	}
	return randomInt(minTarget, maxTarget)
}
