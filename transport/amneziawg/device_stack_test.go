//go:build with_gvisor

package amneziawg

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

type countingDispatcher struct{ delivered int }

func (d *countingDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.delivered++
}

func (d *countingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// The device keeps writing received packets while gVisor detaches the endpoint during teardown.
func TestStackDeviceWriteWithoutDispatcher(t *testing.T) {
	device := &stackDevice{}
	endpoint := (*wireEndpoint)(device)
	packet := [][]byte{{0x45, 0, 0, 20}}
	if count, err := device.Write(packet, 0); count != 1 || err != nil {
		t.Fatalf("before Attach: %d, %v", count, err)
	}
	dispatcher := &countingDispatcher{}
	endpoint.Attach(dispatcher)
	if !endpoint.IsAttached() {
		t.Fatal("not attached")
	}
	if count, err := device.Write(packet, 0); count != 1 || err != nil || dispatcher.delivered != 1 {
		t.Fatalf("attached: %d, %v, delivered %d", count, err, dispatcher.delivered)
	}
	endpoint.Attach(nil)
	if endpoint.IsAttached() {
		t.Fatal("still attached")
	}
	if count, err := device.Write(packet, 0); count != 1 || err != nil || dispatcher.delivered != 1 {
		t.Fatalf("after Attach(nil): %d, %v, delivered %d", count, err, dispatcher.delivered)
	}
}

func TestStackDeviceWriteDuringDetach(t *testing.T) {
	device := &stackDevice{}
	endpoint := (*wireEndpoint)(device)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			endpoint.Attach(&discardDispatcher{})
			endpoint.Attach(nil)
		}
	}()
	packet := [][]byte{{0x60, 0, 0, 0}}
	for {
		select {
		case <-done:
			return
		default:
			device.Write(packet, 0)
		}
	}
}

type discardDispatcher struct{}

func (discardDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (discardDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
