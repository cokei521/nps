package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/logs"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

const defaultPortMappingLeaseSeconds = 3600

const (
	pcpVersion        = 2
	pcpDefaultPort    = 5351
	pcpDefaultTimeout = 2 * time.Second

	pcpCodeOK              pcpResultCode = 0
	pcpCodeNotAuthorized   pcpResultCode = 2
	pcpCodeAddressMismatch pcpResultCode = 12

	pcpOpReply = 0x80
	pcpOpMap   = 1

	pcpUDPMapping = 17
)

type pcpResultCode uint8

func (c pcpResultCode) String() string {
	switch c {
	case pcpCodeOK:
		return "OK"
	case pcpCodeNotAuthorized:
		return "NotAuthorized"
	case pcpCodeAddressMismatch:
		return "AddressMismatch"
	default:
		return fmt.Sprintf("pcpResultCode(%d)", int(c))
	}
}

type pcpMapResponse struct {
	ResultCode   pcpResultCode
	LifetimeSecs uint32
	Epoch        uint32
	ExternalAddr netip.AddrPort
}

type managedPacketConn struct {
	net.PacketConn
	cancelRenew context.CancelFunc
	cleanup     func() error
	closeOnce   sync.Once
}

func (c *managedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.closeOnce.Do(func() {
		if c.cancelRenew != nil {
			c.cancelRenew()
		}
		if c.cleanup != nil {
			_ = c.cleanup()
		}
	})
	return err
}

func maybeEnablePortMapping(ctx context.Context, packetConn net.PacketConn, probe P2PProbeConfig) (net.PacketConn, *PortMappingInfo) {
	if packetConn == nil {
		return nil, nil
	}
	enableUPnP, _ := parseProbeBoolOption(probe.Options, "enable_upnp_portmap")
	enablePCP, _ := parseProbeBoolOption(probe.Options, "enable_pcp_portmap")
	enableNATPMP, _ := parseProbeBoolOption(probe.Options, "enable_natpmp_portmap")
	if !enableUPnP && !enablePCP && !enableNATPMP {
		return packetConn, nil
	}

	internalPort := common.GetPortByAddr(packetConn.LocalAddr().String())
	internalIP := portMappingInternalIP(packetConn.LocalAddr())
	if internalPort <= 0 || internalIP == "" {
		return packetConn, nil
	}

	leaseSeconds, ok := parseProbeIntOption(probe.Options, "portmap_lease_seconds")
	if !ok || leaseSeconds <= 0 {
		leaseSeconds = defaultPortMappingLeaseSeconds
	}

	if enableUPnP {
		if info, cleanup, renew := tryUPnPPortMapping(ctx, internalIP, internalPort, leaseSeconds); info != nil {
			logs.Info("[P2P] port mapping method=%s external=%s internal=%s lease=%ds", info.Method, info.ExternalAddr, info.InternalAddr, info.LeaseSeconds)
			return wrapManagedPacketConn(packetConn, cleanup, renew, leaseSeconds), info
		}
	}
	if enablePCP {
		if info, cleanup, renew := tryPCPPortMapping(ctx, internalIP, internalPort, leaseSeconds); info != nil {
			logs.Info("[P2P] port mapping method=%s external=%s internal=%s lease=%ds", info.Method, info.ExternalAddr, info.InternalAddr, info.LeaseSeconds)
			return wrapManagedPacketConn(packetConn, cleanup, renew, info.LeaseSeconds), info
		}
	}
	if enableNATPMP {
		if info, cleanup, renew := tryNATPMPPortMapping(internalIP, internalPort, leaseSeconds); info != nil {
			logs.Info("[P2P] port mapping method=%s external=%s internal=%s lease=%ds", info.Method, info.ExternalAddr, info.InternalAddr, info.LeaseSeconds)
			return wrapManagedPacketConn(packetConn, cleanup, renew, leaseSeconds), info
		}
	}
	return packetConn, nil
}

func wrapManagedPacketConn(packetConn net.PacketConn, cleanup func() error, renew func() error, leaseSeconds int) net.PacketConn {
	if cleanup == nil && renew == nil {
		return packetConn
	}
	var cancel context.CancelFunc
	if renew != nil && leaseSeconds > 0 {
		var renewCtx context.Context
		renewCtx, cancel = context.WithCancel(context.Background())
		go runPortMappingRenewal(renewCtx, renew, leaseSeconds)
	}
	return &managedPacketConn{
		PacketConn:  packetConn,
		cancelRenew: cancel,
		cleanup:     cleanup,
	}
}

func runPortMappingRenewal(ctx context.Context, renew func() error, leaseSeconds int) {
	if renew == nil || leaseSeconds <= 0 {
		return
	}
	interval := portMappingRenewInterval(leaseSeconds)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := renew(); err != nil {
				logs.Trace("[P2P] port mapping renew failed: %v", err)
			}
		}
	}
}

func portMappingRenewInterval(leaseSeconds int) time.Duration {
	if leaseSeconds <= 0 {
		return time.Second
	}
	lease := time.Duration(leaseSeconds) * time.Second
	interval := lease / 2
	if interval < time.Second {
		interval = time.Second
	}
	if interval >= lease {
		interval = lease * 3 / 4
	}
	if interval <= 0 {
		return 500 * time.Millisecond
	}
	return interval
}

func portMappingInternalIP(localAddr net.Addr) string {
	if localAddr != nil {
		if udpAddr, ok := localAddr.(*net.UDPAddr); ok && udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() && udpAddr.IP.To4() != nil {
			return udpAddr.IP.String()
		}
		ip := net.ParseIP(common.GetIpByAddr(localAddr.String()))
		if ip != nil && !ip.IsUnspecified() && ip.To4() != nil {
			return ip.String()
		}
	}
	if ip, err := common.GetLocalUdp4IP(); err == nil && ip != nil {
		return ip.String()
	}
	return ""
}

func tryUPnPPortMapping(ctx context.Context, internalIP string, internalPort, leaseSeconds int) (*PortMappingInfo, func() error, func() error) {
	if info, cleanup, renew := tryUPnPIGD2(ctx, internalIP, internalPort, leaseSeconds); info != nil {
		return info, cleanup, renew
	}
	if info, cleanup, renew := tryUPnPIGD1(ctx, internalIP, internalPort, leaseSeconds); info != nil {
		return info, cleanup, renew
	}
	if info, cleanup, renew := tryUPnPPPP1(ctx, internalIP, internalPort, leaseSeconds); info != nil {
		return info, cleanup, renew
	}
	return nil, nil, nil
}

func tryUPnPIGD2(ctx context.Context, internalIP string, internalPort, leaseSeconds int) (*PortMappingInfo, func() error, func() error) {
	clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err != nil {
		logs.Trace("[P2P] upnp igd2 discovery failed: %v", err)
		return nil, nil, nil
	}
	for _, client := range clients {
		if client == nil {
			continue
		}
		externalIP, err := client.GetExternalIPAddressCtx(ctx)
		if err != nil || externalIP == "" {
			continue
		}
		externalPort, err := client.AddAnyPortMappingCtx(ctx, "", uint16(internalPort), "UDP", uint16(internalPort), internalIP, true, "nps-p2p", uint32(leaseSeconds))
		if err != nil {
			continue
		}
		info := &PortMappingInfo{
			Method:       "upnp-igd2",
			ExternalAddr: common.BuildAddress(externalIP, strconv.Itoa(int(externalPort))),
			InternalAddr: common.BuildAddress(internalIP, strconv.Itoa(internalPort)),
			LeaseSeconds: leaseSeconds,
		}
		cleanup := func() error {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return client.DeletePortMappingCtx(cleanupCtx, "", externalPort, "UDP")
		}
		renew := func() error {
			renewCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return client.AddPortMappingCtx(renewCtx, "", externalPort, "UDP", uint16(internalPort), internalIP, true, "nps-p2p", uint32(leaseSeconds))
		}
		return info, cleanup, renew
	}
	return nil, nil, nil
}

type upnpPortMapper interface {
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	AddPortMappingCtx(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) error
}

func tryUPnPIGD1(ctx context.Context, internalIP string, internalPort, leaseSeconds int) (*PortMappingInfo, func() error, func() error) {
	clients, _, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil {
		logs.Trace("[P2P] upnp igd1 discovery failed: %v", err)
		return nil, nil, nil
	}
	return tryUPnPStaticPortMapping(ctx, "upnp-igd1", internalIP, internalPort, leaseSeconds, clients)
}

func tryUPnPPPP1(ctx context.Context, internalIP string, internalPort, leaseSeconds int) (*PortMappingInfo, func() error, func() error) {
	clients, _, err := internetgateway1.NewWANPPPConnection1ClientsCtx(ctx)
	if err != nil {
		logs.Trace("[P2P] upnp ppp discovery failed: %v", err)
		return nil, nil, nil
	}
	return tryUPnPStaticPortMapping(ctx, "upnp-ppp1", internalIP, internalPort, leaseSeconds, clients)
}

func tryUPnPStaticPortMapping[T upnpPortMapper](ctx context.Context, method, internalIP string, internalPort, leaseSeconds int, clients []T) (*PortMappingInfo, func() error, func() error) {
	for _, client := range clients {
		externalIP, err := client.GetExternalIPAddressCtx(ctx)
		if err != nil || externalIP == "" {
			continue
		}
		if err := client.AddPortMappingCtx(ctx, "", uint16(internalPort), "UDP", uint16(internalPort), internalIP, true, "nps-p2p", uint32(leaseSeconds)); err != nil {
			continue
		}
		info := &PortMappingInfo{
			Method:       method,
			ExternalAddr: common.BuildAddress(externalIP, strconv.Itoa(internalPort)),
			InternalAddr: common.BuildAddress(internalIP, strconv.Itoa(internalPort)),
			LeaseSeconds: leaseSeconds,
		}
		cleanup := func() error {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return client.DeletePortMappingCtx(cleanupCtx, "", uint16(internalPort), "UDP")
		}
		renew := func() error {
			renewCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return client.AddPortMappingCtx(renewCtx, "", uint16(internalPort), "UDP", uint16(internalPort), internalIP, true, "nps-p2p", uint32(leaseSeconds))
		}
		return info, cleanup, renew
	}
	return nil, nil, nil
}

func tryNATPMPPortMapping(internalIP string, internalPort, leaseSeconds int) (*PortMappingInfo, func() error, func() error) {
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil || gatewayIP == nil {
		logs.Trace("[P2P] nat-pmp gateway discovery failed: %v", err)
		return nil, nil, nil
	}
	client := natpmp.NewClientWithTimeout(gatewayIP, 2*time.Second)
	externalAddress, err := client.GetExternalAddress()
	if err != nil {
		logs.Trace("[P2P] nat-pmp get external address failed: %v", err)
		return nil, nil, nil
	}
	result, err := client.AddPortMapping("udp", internalPort, internalPort, leaseSeconds)
	if err != nil {
		logs.Trace("[P2P] nat-pmp add mapping failed: %v", err)
		return nil, nil, nil
	}
	externalIP := net.IP(externalAddress.ExternalIPAddress[:]).String()
	externalPort := int(result.MappedExternalPort)
	info := &PortMappingInfo{
		Method:       "nat-pmp",
		ExternalAddr: common.BuildAddress(externalIP, strconv.Itoa(externalPort)),
		InternalAddr: common.BuildAddress(internalIP, strconv.Itoa(internalPort)),
		LeaseSeconds: int(result.PortMappingLifetimeInSeconds),
	}
	cleanup := func() error {
		_, err := client.AddPortMapping("udp", internalPort, 0, 0)
		return err
	}
	renew := func() error {
		_, err := client.AddPortMapping("udp", internalPort, externalPort, leaseSeconds)
		return err
	}
	return info, cleanup, renew
}

func tryPCPPortMapping(ctx context.Context, internalIP string, internalPort, leaseSeconds int) (*PortMappingInfo, func() error, func() error) {
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil || gatewayIP == nil {
		logs.Trace("[P2P] pcp gateway discovery failed: %v", err)
		return nil, nil, nil
	}
	clientIP, ok := netip.AddrFromSlice(net.ParseIP(internalIP))
	if !ok {
		logs.Trace("[P2P] pcp invalid internal ip: %s", internalIP)
		return nil, nil, nil
	}
	clientIP = clientIP.Unmap()
	gatewayAddr, ok := netip.AddrFromSlice(gatewayIP)
	if !ok {
		logs.Trace("[P2P] pcp invalid gateway ip: %v", gatewayIP)
		return nil, nil, nil
	}
	gatewayAddr = gatewayAddr.Unmap()
	gatewayAP := netip.AddrPortFrom(gatewayAddr, pcpDefaultPort)

	response, err := requestPCPMap(ctx, gatewayAP, clientIP, uint16(internalPort), 0, leaseSeconds, netip.Addr{})
	if err != nil {
		logs.Trace("[P2P] pcp add mapping failed: %v", err)
		return nil, nil, nil
	}
	externalAddr := response.ExternalAddr
	if !externalAddr.IsValid() {
		return nil, nil, nil
	}
	lifetime := int(response.LifetimeSecs)
	if lifetime <= 0 {
		lifetime = leaseSeconds
	}
	info := &PortMappingInfo{
		Method:       "pcp",
		ExternalAddr: externalAddr.String(),
		InternalAddr: common.BuildAddress(internalIP, strconv.Itoa(internalPort)),
		LeaseSeconds: lifetime,
	}
	cleanup := func() error {
		releaseCtx, cancel := context.WithTimeout(context.Background(), pcpDefaultTimeout)
		defer cancel()
		_, err := requestPCPMap(releaseCtx, gatewayAP, clientIP, uint16(internalPort), externalAddr.Port(), 0, externalAddr.Addr())
		return err
	}
	renew := func() error {
		renewCtx, cancel := context.WithTimeout(context.Background(), pcpDefaultTimeout)
		defer cancel()
		_, err := requestPCPMap(renewCtx, gatewayAP, clientIP, uint16(internalPort), externalAddr.Port(), lifetime, externalAddr.Addr())
		return err
	}
	return info, cleanup, renew
}

func requestPCPMap(ctx context.Context, gatewayAP netip.AddrPort, clientIP netip.Addr, localPort, prevExternalPort uint16, lifetimeSec int, prevExternalIP netip.Addr) (*pcpMapResponse, error) {
	if !gatewayAP.IsValid() || !clientIP.IsValid() || localPort == 0 {
		return nil, fmt.Errorf("invalid pcp request parameters")
	}
	if lifetimeSec < 0 {
		lifetimeSec = 0
	}
	request, nonce := buildPCPRequestMappingPacket(clientIP, localPort, prevExternalPort, uint32(lifetimeSec), prevExternalIP)
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(pcpDefaultTimeout))
	}
	if _, err := conn.WriteToUDPAddrPort(request, gatewayAP); err != nil {
		return nil, err
	}
	buf := make([]byte, 128)
	n, _, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, err
	}
	return parsePCPMapResponse(buf[:n], nonce)
}

func buildPCPRequestMappingPacket(myIP netip.Addr, localPort, prevPort uint16, lifetimeSec uint32, prevExternalIP netip.Addr) ([]byte, [12]byte) {
	pkt := make([]byte, 24+36)
	pkt[0] = pcpVersion
	pkt[1] = pcpOpMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSec)
	myIP16 := myIP.As16()
	copy(pkt[8:24], myIP16[:])

	mapOp := pkt[24:]
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	copy(mapOp[:12], nonce[:])
	mapOp[12] = pcpUDPMapping
	binary.BigEndian.PutUint16(mapOp[16:18], localPort)
	binary.BigEndian.PutUint16(mapOp[18:20], prevPort)
	if prevExternalIP.IsValid() {
		prevExternalIP16 := prevExternalIP.As16()
		copy(mapOp[20:], prevExternalIP16[:])
	}
	return pkt, nonce
}

func parsePCPMapResponse(resp []byte, expectedNonce [12]byte) (*pcpMapResponse, error) {
	if len(resp) < 60 {
		return nil, fmt.Errorf("invalid pcp map response length")
	}
	if resp[0] != pcpVersion || resp[1] != (pcpOpMap|pcpOpReply) {
		return nil, fmt.Errorf("invalid pcp response opcode")
	}
	code := pcpResultCode(resp[3])
	if code == pcpCodeNotAuthorized {
		return nil, fmt.Errorf("pcp not authorized")
	}
	if code != pcpCodeOK {
		return nil, fmt.Errorf("pcp response code %s", code)
	}
	var actualNonce [12]byte
	copy(actualNonce[:], resp[24:36])
	if actualNonce != expectedNonce {
		return nil, fmt.Errorf("pcp response nonce mismatch")
	}
	result := &pcpMapResponse{
		ResultCode:   code,
		LifetimeSecs: binary.BigEndian.Uint32(resp[4:8]),
		Epoch:        binary.BigEndian.Uint32(resp[8:12]),
	}
	var externalIP16 [16]byte
	copy(externalIP16[:], resp[44:60])
	externalIP := netip.AddrFrom16(externalIP16).Unmap()
	externalPort := binary.BigEndian.Uint16(resp[42:44])
	if !externalIP.IsValid() || externalPort == 0 {
		return nil, fmt.Errorf("pcp response missing external mapping")
	}
	result.ExternalAddr = netip.AddrPortFrom(externalIP, externalPort)
	return result, nil
}
