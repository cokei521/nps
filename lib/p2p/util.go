package p2p

import "strings"

func isIgnorableUDPIcmpError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connection reset by peer") {
		return true
	}
	if strings.Contains(errStr, "wsarecvfrom") && (strings.Contains(errStr, "10054") || strings.Contains(errStr, "wsaeconnreset")) {
		return true
	}
	return false
}
