package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/gardener/vpn2/pkg/config"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	uapiConfTpl = `private_key=%s
listen_port=%d
public_key=%s
allowed_ip=%s
persistent_keepalive_interval=25
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
	return start(ctx, log.WithName("wireguard-server"), wireguardConfig{
		ip:         cfg.VPNNetwork.IP.String(),
		privateKey: cfg.WGPrivateKey,
		publicKey:  cfg.WGPublicKey,
		port:       cfg.WGPort,
	})
}

func StartClient(ctx context.Context, log logr.Logger, cfg config.VPNClient) error {
	return start(ctx, log.WithName("wireguard-client"), wireguardConfig{
		ip:         cfg.VPNNetwork.IP.String(),
		privateKey: cfg.WGPrivateKey,
		publicKey:  cfg.WGPublicKey,
		port:       cfg.WGPort,
	})
}

func start(ctx context.Context, log logr.Logger, cfg wireguardConfig) error {
	localTunnelAddress, err := netip.ParseAddr(cfg.ip)
	if err != nil {
		return err
	}

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

	var (
		publicKey wgtypes.Key
	)
	privateKey, err := generateKeyPair()
	if err != nil {
		return err
	}

	if cfg.privateKey != "" {
		privateKey, err = wgtypes.ParseKey(cfg.privateKey)
		if err != nil {
			return fmt.Errorf("unable to parse private key:%w", err)
		}
	}
	if cfg.publicKey != "" {
		publicKey, err = wgtypes.ParseKey(cfg.publicKey)
		if err != nil {
			return fmt.Errorf("unable to parse private key:%w", err)
		}
	} else {
		publicKey = privateKey.PublicKey()
	}

	publicKeyString := hex.EncodeToString(publicKey[:])
	privateKeyString := hex.EncodeToString(privateKey[:])

	log.Info("starting wireguard with", "privatekey", privateKeyString, "publickey", publicKeyString)

	uapiConf := fmt.Sprintf(uapiConfTpl, privateKeyString, cfg.port, publicKeyString, allowedIPs)

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	err = dev.IpcSet(uapiConf)
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

func generateKeyPair() (wgtypes.Key, error) {

	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}

	return private, nil
}
