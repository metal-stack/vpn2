package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/davecgh/go-spew/spew"
	"github.com/gardener/vpn2/pkg/config"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	serverUapiConfTpl = `private_key=%s
listen_port=%d
public_key=%s
allowed_ip=%s
persistent_keepalive_interval=25
`
	clientUapiConfTpl = `private_key=%s
public_key=%s
allowed_ip=%s
endpoint=%s:%d
`
	allowedIPs = "0.0.0.0/0"
)

type wireguardConfig struct {
	ip         string
	publicKey  string
	privateKey string
	port       int
}

func StartServer(ctx context.Context, log logr.Logger, cfg config.VPNServer) error {
	uapiConf := fmt.Sprintf(serverUapiConfTpl, cfg.WGPrivateKey, cfg.WGPort, cfg.WGPublicKey, allowedIPs)

	return start(ctx, log.WithName("wireguard-server"), uapiConf, wireguardConfig{
		ip:         cfg.VPNNetwork.IP.String(),
		privateKey: cfg.WGPrivateKey,
		publicKey:  cfg.WGPublicKey,
		port:       cfg.WGPort,
	})
}

func StartClient(ctx context.Context, log logr.Logger, cfg config.VPNClient) error {
	ips, err := net.LookupIP(cfg.Endpoint)
	if err != nil {
		return err
	}

	log.Info("resolved endpoint, using first ip in slice", "endpoint", cfg.Endpoint, "ips", ips)

	uapiConf := fmt.Sprintf(clientUapiConfTpl, cfg.WGPrivateKey, cfg.WGPublicKey, allowedIPs, "172.18.255.1", cfg.WGPort) // FIXME

	spew.Dump(uapiConf)

	return start(ctx, log.WithName("wireguard-client"), uapiConf, wireguardConfig{
		ip:         cfg.VPNNetwork.IP.String(),
		privateKey: cfg.WGPrivateKey,
		publicKey:  cfg.WGPublicKey,
		port:       cfg.WGPort,
	})
}

func start(ctx context.Context, log logr.Logger, uapi string, cfg wireguardConfig) error {
	localTunnelAddress, err := netip.ParseAddr(cfg.ip)
	if err != nil {
		return err
	}

	if cfg.privateKey == "" || cfg.publicKey == "" {
		return fmt.Errorf("private and public key must be not empty")
	}

	log.Info("starting wireguard with", "privatekey", cfg.privateKey, "publickey", cfg.publicKey)

	// Create a wireguard tunnel interface
	tun, _, err := netstack.CreateNetTUN(
		[]netip.Addr{localTunnelAddress}, // Only true for the non HA case, otherwise 2 disjunct IPs must be created and a listener attached
		[]netip.Addr{},                   // No DNS Servers required for our use case
		1420,
	)
	if err != nil {
		return fmt.Errorf("unable to create the wireguard interface:%w", err)
	}

	tunnelName, err := tun.Name()
	if err != nil {
		return fmt.Errorf("unable to get name of wireguard interface:%w", err)
	}

	log.Info("created wireguard tunnel device", "device", tunnelName)

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	err = dev.IpcSet(uapi)
	if err != nil {
		return fmt.Errorf("unable to set wireguard configuration:%w", err)
	}
	err = dev.Up()
	if err != nil {
		return fmt.Errorf("unable to bring up wireguard tunnel device:%w", err)
	}
	<-ctx.Done()

	return nil
}
