// Package vnet wraps a userspace TCP/IP stack (gVisor, via the wireguard-go
// netstack helper) so that IP packets carried over the SSTP/PPP tunnel can be
// used to originate ordinary TCP connections — without any TUN device or
// system-wide routing changes.
package vnet

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Net is a userspace network bound to the tunnel's assigned IP address.
type Net struct {
	dev tun.Device
	tn  *netstack.Net
	mtu int
}

// New builds the userspace stack using the negotiated local IP and DNS servers.
func New(localIP net.IP, dns []net.IP, mtu int) (*Net, error) {
	ip4 := localIP.To4()
	if ip4 == nil {
		return nil, errors.New("vnet: only IPv4 tunnel addresses are supported")
	}
	local, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return nil, errors.New("vnet: invalid local IP")
	}
	var dnsAddrs []netip.Addr
	for _, d := range dns {
		if d4 := d.To4(); d4 != nil {
			if a, ok := netip.AddrFromSlice(d4); ok && !a.IsUnspecified() {
				dnsAddrs = append(dnsAddrs, a)
			}
		}
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}
	}
	if mtu <= 0 {
		mtu = 1400
	}
	dev, tn, err := netstack.CreateNetTUN([]netip.Addr{local}, dnsAddrs, mtu)
	if err != nil {
		return nil, err
	}
	return &Net{dev: dev, tn: tn, mtu: mtu}, nil
}

// WriteInbound injects an IP packet received from the tunnel into the stack.
func (n *Net) WriteInbound(pkt []byte) error {
	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	_, err := n.dev.Write([][]byte{buf}, 0)
	return err
}

// ReadOutbound blocks until the stack produces an IP packet that must be sent
// out over the tunnel.
func (n *Net) ReadOutbound() ([]byte, error) {
	bufs := [][]byte{make([]byte, n.mtu+128)}
	sizes := make([]int, 1)
	count, err := n.dev.Read(bufs, sizes, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 || sizes[0] == 0 {
		return nil, nil
	}
	out := make([]byte, sizes[0])
	copy(out, bufs[0][:sizes[0]])
	return out, nil
}

// DialContext dials a TCP connection through the tunnel. host may be a domain
// name (resolved through the tunnel's DNS servers) or an IP literal.
func (n *Net) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return n.tn.DialContext(ctx, network, addr)
}

// Close releases the stack.
func (n *Net) Close() error { return n.dev.Close() }
