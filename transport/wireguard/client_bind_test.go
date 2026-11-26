package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

// overlapConn stands in for a detour packet connection and counts writes that overlap.
type overlapConn struct {
	net.PacketConn
	active   atomic.Int32
	overlaps atomic.Int32
}

func (c *overlapConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.active.Add(1) > 1 {
		c.overlaps.Add(1)
	}
	time.Sleep(20 * time.Microsecond)
	c.active.Add(-1)
	return len(b), nil
}

func (c *overlapConn) Close() error { return nil }

type overlapDialer struct{ conn *overlapConn }

func (d overlapDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (d overlapDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return d.conn, nil
}

// The device sends from one goroutine per peer; a detour connection must see one write at a time.
func TestClientBindSerializesDetourWrites(t *testing.T) {
	detour := &overlapConn{}
	address := netip.MustParseAddrPort("192.0.2.1:51820")
	bind := NewClientBind(context.Background(), log.StdLogger(), overlapDialer{detour}, M.SocksaddrFromNetIP(address), [3]uint8{})
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	var senders sync.WaitGroup
	for range 8 {
		senders.Go(func() {
			for range 50 {
				if err := bind.Send([][]byte{{1, 0, 0, 0, 1}}, remoteEndpoint(address), 0); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	senders.Wait()
	if overlaps := detour.overlaps.Load(); overlaps != 0 {
		t.Fatalf("%d overlapping writes on the detour connection", overlaps)
	}
}
