package proxy

import (
	"errors"
	"net"
	"runtime"
)

type P2PServer struct {
	basePort   int
	extraReply bool
	listeners  []*net.UDPConn
	ports      []int
	workers    chan struct{}
}

func NewP2PServer(basePort int, extraReply bool) *P2PServer {
	workerCount := runtime.GOMAXPROCS(0) * 32
	if workerCount < 64 {
		workerCount = 64
	}
	return &P2PServer{
		basePort:   basePort,
		extraReply: extraReply,
		workers:    make(chan struct{}, workerCount),
	}
}

func (s *P2PServer) Start() error {
	ports := []int{s.basePort, s.basePort + 1, s.basePort + 2}
	s.listeners = make([]*net.UDPConn, 0, len(ports))
	s.ports = make([]int, 0, len(ports)*2)
	for _, port := range ports {
		listeners, err := listenProbeListeners(port)
		if err != nil {
			_ = s.Close()
			return err
		}
		for _, listener := range listeners {
			s.listeners = append(s.listeners, listener)
			s.ports = append(s.ports, port)
		}
	}

	errCh := make(chan error, len(s.listeners))
	for i, listener := range s.listeners {
		go s.serveListener(listener, s.ports[i], errCh)
	}
	err := <-errCh
	if err != nil && !errors.Is(err, net.ErrClosed) {
		_ = s.Close()
		return err
	}
	return nil
}

func (s *P2PServer) Close() error {
	var closeErr error
	for _, listener := range s.listeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = err
		}
	}
	return closeErr
}
