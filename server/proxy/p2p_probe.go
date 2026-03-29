package proxy

import (
	"net"
	"strings"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/p2p"
	"github.com/djylb/nps/server/p2pstate"
)

func (s *P2PServer) serveListener(listener *net.UDPConn, listenPort int, errCh chan<- error) {
	for {
		buf := common.BufPoolUdp.Get()
		n, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			common.BufPoolUdp.Put(buf)
			logs.Trace("[P2P] probe listener read err port=%d err=%v", listenPort, err)
			errCh <- err
			return
		}
		s.workers <- struct{}{}
		go func(packetBuf []byte, packetLen int, packetAddr *net.UDPAddr) {
			defer func() {
				common.BufPoolUdp.Put(packetBuf)
				<-s.workers
			}()
			s.handleProbe(listener, listenPort, packetAddr, packetBuf[:packetLen])
		}(buf, n, addr)
	}
}

func (s *P2PServer) handleProbe(listener *net.UDPConn, listenPort int, addr *net.UDPAddr, data []byte) {
	packet, err := p2p.DecodeUDPPacketWithLookup(data, p2pstate.LookupSession)
	if err != nil {
		return
	}
	if packet.Type != "probe" {
		return
	}
	if !p2pstate.AcceptPacket(packet.WireID, packet.Timestamp, packet.Nonce) {
		return
	}

	logs.Trace("[P2P] probe from=%s observed public port=%d", addr.String(), addr.Port)
	p2pstate.RecordObservation(packet.WireID, packet.Role, p2p.ProbeSample{
		Provider:        p2p.ProbeProviderNPS,
		Mode:            p2p.ProbeModeUDP,
		ProbePort:       listenPort,
		ObservedAddr:    addr.String(),
		ServerReplyAddr: listener.LocalAddr().String(),
	})

	ack := p2p.NewProbeAckPacketWithWire(packet.SessionID, packet.Token, packet.Role, listenPort, addr.String(), false, p2p.P2PWireSpec{RouteID: packet.WireID})
	raw, err := p2p.EncodeUDPPacket(ack)
	if err == nil {
		_, _ = listener.WriteToUDP(raw, addr)
	}

	if !s.extraReply {
		return
	}
	s.sendExtraReply(listenPort, addr, packet)
}

func (s *P2PServer) sendExtraReply(listenPort int, target *net.UDPAddr, packet *p2p.UDPPacket) {
	if target == nil || packet == nil {
		return
	}
	network := "udp4"
	if target.IP != nil && target.IP.To4() == nil {
		network = "udp6"
	}
	extraConn, err := net.ListenUDP(network, nil)
	if err != nil {
		logs.Trace("[P2P] extra reply fail port=%d target=%s err=%v", listenPort, target.String(), err)
		return
	}
	defer func() { _ = extraConn.Close() }()
	_ = extraConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	extraAck := p2p.NewProbeAckPacketWithWire(packet.SessionID, packet.Token, packet.Role, listenPort, target.String(), true, p2p.P2PWireSpec{RouteID: packet.WireID})
	extraRaw, err := p2p.EncodeUDPPacket(extraAck)
	if err != nil {
		logs.Trace("[P2P] extra reply fail port=%d target=%s err=%v", listenPort, target.String(), err)
		return
	}
	if _, err := extraConn.WriteToUDP(extraRaw, target); err == nil {
		logs.Trace("[P2P] extra reply success port=%d target=%s", listenPort, target.String())
	} else {
		logs.Trace("[P2P] extra reply fail port=%d target=%s err=%v", listenPort, target.String(), err)
	}
}

func listenProbeListeners(port int) ([]*net.UDPConn, error) {
	listeners := make([]*net.UDPConn, 0, 2)
	v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, err
	}
	listeners = append(listeners, v4)
	logs.Info("start p2p probe listener network=udp4 port %d", port)

	if v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: port}); err == nil {
		listeners = append(listeners, v6)
		logs.Info("start p2p probe listener network=udp6 port %d", port)
	} else if isOptionalIPv6ListenErr(err) {
		logs.Trace("[P2P] skip udp6 probe listener port=%d err=%v", port, err)
	} else {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		return nil, err
	}
	return listeners, nil
}

func isOptionalIPv6ListenErr(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "address already in use") ||
		strings.Contains(message, "address family not supported") ||
		strings.Contains(message, "cannot assign requested address") ||
		strings.Contains(message, "no such device")
}
