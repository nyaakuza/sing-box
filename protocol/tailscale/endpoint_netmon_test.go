//go:build with_gvisor

package tailscale

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/tailscale/net/netmon"
)

type netmonTestNetworkManager struct {
	adapter.NetworkManager
}

func (netmonTestNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return netmonTestInterfaceMonitor{}
}

func (netmonTestNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return netmonTestInterfaceFinder{}
}

func (netmonTestNetworkManager) AutoDetectInterfaceFunc() control.Func { return nil }

func (netmonTestNetworkManager) AutoRedirectOutputMark() uint32 { return 0 }

type netmonTestInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
}

func (netmonTestInterfaceMonitor) DefaultInterface() *control.Interface { return nil }

type netmonTestInterfaceFinder struct {
	control.InterfaceFinder
}

func (netmonTestInterfaceFinder) Interfaces() []control.Interface { return nil }

// libcore registers its own netmon getter before start on Android, where netlink interface listing is denied.
func TestStartKeepsNetmonOverridesWithoutPlatformInterfaces(t *testing.T) {
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		return []netmon.Interface{{Interface: &net.Interface{Name: "platform0"}}}, nil
	})
	netmon.SetDefaultRouteFunc(func() (netmon.DefaultRouteDetails, error) {
		return netmon.DefaultRouteDetails{InterfaceName: "platform0"}, nil
	})
	t.Cleanup(func() {
		netmon.RegisterInterfaceGetter(nil)
		netmon.SetDefaultRouteFunc(nil)
	})

	endpoint := &Endpoint{network: netmonTestNetworkManager{}}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	defer scope.Close()
	if err := endpoint.start(scope); err != nil {
		t.Fatal(err)
	}

	interfaces, err := netmon.GetInterfaceList()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "platform0" {
		t.Fatalf("interface getter replaced: %v, %v", interfaces, err)
	}
	route, err := netmon.DefaultRoute()
	if err != nil || route.InterfaceName != "platform0" {
		t.Fatalf("default route function replaced: %+v, %v", route, err)
	}
}
