package amneziawg

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ conn.Bind = (*ClientBind)(nil)

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                *wireConn
	done                chan struct{}
	destination         M.Socksaddr
	reserved            [3]uint8
	rewriteReserved     bool
	// The device sends from one goroutine per peer, and detour packet connections (VLESS, for one)
	// are not all safe for concurrent writes; a plain UDP socket is.
	serializeWrites bool
	writeAccess     sync.Mutex
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, destination M.Socksaddr, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		destination:         destination,
		serializeWrites:     !isUDPListener(dialer),
		reserved:            reserved,
		rewriteReserved:     reserved != [3]uint8{},
	}
}

func isUDPListener(d N.Dialer) bool {
	_, isListener := common.Cast[dialer.UDPListener](d)
	return isListener
}

func (c *ClientBind) connect() (*wireConn, error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn := c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	// A listening socket, not a connected one: the kernel would drop a peer's replies from its other addresses.
	udpConn, err := c.dialer.ListenPacket(c.bindCtx, c.destination)
	if err != nil {
		return nil, err
	}
	c.conn = &wireConn{
		PacketConn: bufio.NewPacketConn(udpConn),
		done:       make(chan struct{}),
	}
	return c.conn, nil
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *ClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connect()
	if err != nil {
		select {
		case <-c.done:
			return
		default:
		}
		c.logger.Error(E.Cause(err, "connect to server"))
		err = nil
		select {
		case <-c.done:
		case <-time.After(time.Second):
		}
		return
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		udpConn.Close()
		select {
		case <-c.done:
		default:
			c.logger.Error(E.Cause(err, "read packet"))
			err = nil
		}
		return
	}
	sizes[0] = n
	c.connAccess.Lock()
	rewriteReserved := c.rewriteReserved
	c.connAccess.Unlock()
	if n > 3 && rewriteReserved {
		b := packets[0]
		common.ClearArray(b[1:4])
	}
	eps[0] = remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort())
	count = 1
	return
}

func (c *ClientBind) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	common.Close(common.PtrOrNil(c.conn))
	return nil
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	udpConn, err := c.connect()
	if err != nil {
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	c.connAccess.Lock()
	rewriteReserved := c.rewriteReserved
	reserved, loaded := c.reservedForEndpoint[destination]
	if !loaded {
		reserved = c.reserved
	}
	c.connAccess.Unlock()
	for _, b := range bufs {
		if len(b) > 3 && rewriteReserved {
			copy(b[1:4], reserved[:])
		}
		if c.serializeWrites {
			c.writeAccess.Lock()
		}
		_, err = udpConn.WriteTo(b, M.SocksaddrFromNetIP(destination).UDPAddr())
		if c.serializeWrites {
			c.writeAccess.Unlock()
		}
		if err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

func (c *ClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint(ap), nil
}

func (c *ClientBind) BatchSize() int {
	return 1
}

func (c *ClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	c.reservedForEndpoint[destination] = reserved
	if reserved != [3]byte{} {
		c.rewriteReserved = true
	}
}

type wireConn struct {
	net.PacketConn
	access sync.Mutex
	done   chan struct{}
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	w.PacketConn.Close()
	close(w.done)
	return nil
}

var _ conn.Endpoint = (*remoteEndpoint)(nil)

type remoteEndpoint netip.AddrPort

func (e remoteEndpoint) ClearSrc() {
}

func (e remoteEndpoint) SrcToString() string {
	return ""
}

func (e remoteEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
