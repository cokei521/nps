package p2p

import (
	"net"

	"github.com/djylb/nps/lib/common"
)

type udpAddrFamily uint8

const (
	udpFamilyAny udpAddrFamily = iota
	udpFamilyV4
	udpFamilyV6
)

func detectAddrFamily(addr net.Addr) udpAddrFamily {
	return detectIPFamily(common.ParseIPFromAddr(addrString(addr)))
}

func detectAddressFamily(addr string) udpAddrFamily {
	return detectIPFamily(common.ParseIPFromAddr(addr))
}

func detectIPFamily(ip net.IP) udpAddrFamily {
	ip = common.NormalizeIP(ip)
	if ip == nil {
		return udpFamilyAny
	}
	if ip.To4() != nil {
		return udpFamilyV4
	}
	return udpFamilyV6
}

func (f udpAddrFamily) matchesAddr(addr string) bool {
	targetFamily := detectAddressFamily(addr)
	return f == udpFamilyAny || targetFamily == udpFamilyAny || f == targetFamily
}

func (f udpAddrFamily) matchesIP(ip net.IP) bool {
	targetFamily := detectIPFamily(ip)
	return f == udpFamilyAny || targetFamily == udpFamilyAny || f == targetFamily
}

func (f udpAddrFamily) network() string {
	switch f {
	case udpFamilyV4:
		return "udp4"
	case udpFamilyV6:
		return "udp6"
	default:
		return "udp"
	}
}
