package media

import (
	"errors"
	"net"
	"sync"
)

// PortPool hands out even/odd (RTP/RTCP) port pairs from a fixed range.
// Freed pairs go to the back of the queue so a port isn't reused right away,
// which keeps stray packets from a finished call out of the next one.
type PortPool struct {
	mu   sync.Mutex
	free []int // even RTP ports; RTCP is +1
}

func NewPortPool(min, max int) *PortPool {
	p := &PortPool{}
	if min%2 == 1 {
		min++
	}
	for port := min; port+1 <= max; port += 2 {
		p.free = append(p.free, port)
	}
	return p
}

// Available reports how many port pairs are free (one per endpoint).
func (p *PortPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.free)
}

var ErrNoPorts = errors.New("media: no free RTP ports")

// allocate binds an RTP/RTCP socket pair, skipping ports something else holds.
func (p *PortPool) allocate() (port int, rtp, rtcp *net.UDPConn, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for tries := len(p.free); tries > 0; tries-- {
		port, p.free = p.free[0], p.free[1:]
		rtp, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			p.free = append(p.free, port)
			continue
		}
		rtcp, err = net.ListenUDP("udp", &net.UDPAddr{Port: port + 1})
		if err != nil {
			rtp.Close()
			p.free = append(p.free, port)
			continue
		}
		return port, rtp, rtcp, nil
	}
	return 0, nil, nil, ErrNoPorts
}

func (p *PortPool) release(port int) {
	p.mu.Lock()
	p.free = append(p.free, port)
	p.mu.Unlock()
}
