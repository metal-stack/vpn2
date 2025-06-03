package wireguard

import (
	"net"
	"testing"

	"github.com/gardener/vpn2/pkg/config"
	"github.com/gardener/vpn2/pkg/network"
	"github.com/go-logr/logr"
)

func TestStartWireguardServer(t *testing.T) {

	log := logr.New(logr.Discard().GetSink())

	ip, _, err := net.ParseCIDR("fd8f:6d53:b97a:1::/96")
	if err != nil {
		t.Fail()
	}

	tests := []struct {
		name    string
		cfg     config.VPNServer
		wantErr bool
	}{
		// {
		// 	name: "simple",
		// 	cfg: config.VPNServer{
		// 		VPNNetwork: network.CIDR{IP: ip},
		// 		WGPort:     51820,
		// 	},
		// 	wantErr: false,
		// },
		{
			name: "given private key",
			cfg: config.VPNServer{
				VPNNetwork:   network.CIDR{IP: ip},
				WGPrivateKey: "38f84d8469bb677b277dd879b67c50a5117643d46df2f7900aa218099174244f",
				WGPort:       51820,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := StartServer(t.Context(), log, tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("StartWireguardServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
