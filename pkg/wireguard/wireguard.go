package wireguard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gardener/vpn2/pkg/config"
	"github.com/gardener/vpn2/pkg/constants"
	"github.com/gardener/vpn2/pkg/network"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/vishvananda/netlink"

)


const (
	uapiServerConfTpl = `private_key=%s
listen_port=%d
public_key=%s
allowed_ip=%s
persistent_keepalive_interval=25
`
	uapiClientConfTpl = `private_key=%s
listen_port=%d
public_key=%s
allowed_ip=%s
endpoint=%s
persistent_keepalive_interval=25
`
	allowedIPs = "0.0.0.0/0"
)

type wireguardConfig struct {
	ip              network.CIDR
	publicKey       string
	privateKey      string
	port            int
	seedPodNetwork  network.CIDR
	podNetworks     []network.CIDR
	serviceNetworks []network.CIDR
	nodeNetworks    []network.CIDR
	endpoint        string
}

func StartServer(ctx context.Context, log logr.Logger, cfg config.VPNServer) error {
	return start(ctx, log.WithName("wireguard-server"), wireguardConfig{
		ip:              cfg.VPNNetwork,
		privateKey:      cfg.WGPrivateKey,
		publicKey:       cfg.WGPublicKey,
		port:            cfg.WGPort,
		seedPodNetwork:  cfg.SeedPodNetwork,
		podNetworks:     cfg.PodNetworks,
		serviceNetworks: cfg.ServiceNetworks,
		nodeNetworks:    cfg.NodeNetworks,
	})
}

func StartClient(ctx context.Context, log logr.Logger, cfg config.VPNClient) error {
	return start(ctx, log.WithName("wireguard-client"), wireguardConfig{
		ip:             cfg.VPNNetwork,
		privateKey:     cfg.WGPrivateKey,
		publicKey:      cfg.WGPublicKey,
		port:           cfg.WGPort,
		seedPodNetwork: cfg.SeedPodNetwork,
		endpoint:       cfg.Endpoint,
	})
}

func start(ctx context.Context, log logr.Logger, cfg wireguardConfig) error {

	tunDev, err := tun.CreateTUN("wg0", device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("unable to create the wireguard interface: %w", err)
	}

	tunnelName, err := tunDev.Name()
	if err != nil {
		return fmt.Errorf("unable to get name of wireguard interface:%w", err)
	}

	log.Info("created wireguard tunnel device", "device", tunnelName)

	var (
		publicKey wgtypes.Key
	)

	server := cfg.podNetworks != nil

	privateKey, err := generateKeyPair()
	if err != nil {
		return err
	}

	if cfg.privateKey != "" {
		pk, err := hex.DecodeString(cfg.privateKey)
		if err != nil {
			return err
		}
		privateKey, err = wgtypes.NewKey(pk)
		if err != nil {
			return fmt.Errorf("unable to parse private key:%w", err)
		}
	}
	if cfg.publicKey != "" {
		pk, err := hex.DecodeString(cfg.publicKey)
		if err != nil {
			return err
		}
		publicKey, err = wgtypes.NewKey(pk)
		if err != nil {
			return fmt.Errorf("unable to parse private key:%w", err)
		}
	} else {
		publicKey = privateKey.PublicKey()
	}

	publicKeyString := hex.EncodeToString(publicKey[:])
	privateKeyString := hex.EncodeToString(privateKey[:])

	log.Info("starting wireguard with", "privatekey", privateKeyString, "publickey", publicKeyString)

	var endpointIP string
	if cfg.endpoint != "" {
		host, port, err := net.SplitHostPort(cfg.endpoint)
		if err != nil {
			// If no port is specified, treat the whole string as host
			host = cfg.endpoint
			port = fmt.Sprintf("%d", cfg.port)
		}
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("failed to resolve endpoint %s: %w", host, err)
		}
		// Use the first resolved IP
		endpointIP = net.JoinHostPort(ips[0].String(), port)
	}

	uapiConf := fmt.Sprintf(uapiClientConfTpl, privateKeyString, cfg.port, publicKeyString, allowedIPs, endpointIP)
	if server {
		uapiConf = fmt.Sprintf(uapiServerConfTpl, privateKeyString, cfg.port, publicKeyString, allowedIPs)
	}

	log.Info("Wireguard configuration", "config", uapiConf)

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	log.Info("Device started")

	err = dev.IpcSet(uapiConf)
	if err != nil {
		return fmt.Errorf("unable to set wireguard configuration:%w", err)
	}

	// Add IP address to wg0
	link, err := netlink.LinkByName("wg0")
	if err != nil {
		return fmt.Errorf("failed to get wg0 link: %w", err)
	}

	addr := &netlink.Addr{IPNet: cfg.ip.ToIPNet()}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add address %s to wg0: %w", cfg.ip, err)
	}

	err = dev.Up()
	if err != nil {
		return fmt.Errorf("unable to bring up wireguard tunnel device:%w", err)
	}

	if cfg.podNetworks != nil /*&& cfg.nodeNetworks != nil && cfg.serviceNetworks != nil*/ {
		// var networks []string
		// for _, nw := range cfg.podNetworks {
		// 	networks = append(networks, nw.String())
		// }
		// for _, nw := range cfg.serviceNetworks {
		// 	networks = append(networks, nw.String())
		// }
		// if cfg.nodeNetworks != nil {
		// 	for _, nw := range cfg.nodeNetworks {
		// 		networks = append(networks, nw.String())
		// 	}
		// }

		networks := []string{
			network.ParseIPNetIgnoreError(constants.ShootPodNetworkMapped).String(),
			network.ParseIPNetIgnoreError(constants.ShootServiceNetworkMapped).String(),
			network.ParseIPNetIgnoreError(constants.ShootNodeNetworkMapped).String(),
		}

		log.Info("setting up firewall rules for wireguard", "networks", networks, "seedPodNetwork", cfg.seedPodNetwork.String())
		err = runFirewallCommand(log, tunnelName, "up", networks, cfg.seedPodNetwork.String())
		if err != nil {
			return fmt.Errorf("failed to set up firewall rules: %w", err)
		}
		log.Info("firewall rules for wireguard set up successfully", "networks", networks, "seedPodNetwork", cfg.seedPodNetwork.String())
	} else {
		// this is the client
		dev, err := netlink.LinkByName("wg0")
		if err != nil {
			return err
		}
		// Check if the device is up, and set it up if not
		if dev.Attrs().Flags&net.FlagUp == 0 {
			if err := netlink.LinkSetUp(dev); err != nil {
				return fmt.Errorf("failed to set wg0 up: %w", err)
			}
		}
		_, ipnet, err := net.ParseCIDR(constants.SeedPodNetworkMapped)
		if err != nil {
			return fmt.Errorf("parsing network %s failed: %s", constants.SeedPodNetworkMapped, err)
		}
		if err := network.ReplaceRoute(log, ipnet, dev); err != nil {
			return err
		}
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

func runFirewallCommand(log logr.Logger, device, mode string, networks []string, seedPodNetwork string) error {

	if err := os.Setenv("PATH", "/sbin"); err != nil {
		return fmt.Errorf("setting PATH environment variable failed: %w", err)
	}
	iptable4, err := network.NewIPTables(log, iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	iptable6, err := network.NewIPTables(log, iptables.ProtocolIPv6)
	if err != nil {
		return err
	}

	var op4, op6 func(table, chain string, spec ...string) error
	var opName string
	switch mode {
	case "up":
		op4 = iptable4.Append
		op6 = iptable6.Append
		opName = "-A"
	case "down":
		op4 = iptable4.DeleteIfExists
		op6 = iptable6.DeleteIfExists
		opName = "-D"
	default:
		return errors.New("mode flag must be down or up")
	}

	for _, spec := range [][]string{
		{"-m", "state", "--state", "RELATED,ESTABLISHED", "-i", device, "-j", "ACCEPT"},
		{"-i", device, "-j", "DROP"},
	} {
		if err := op4("filter", "INPUT", spec...); err != nil {
			return err
		}
		if err := op6("filter", "INPUT", spec...); err != nil {
			return err
		}
		log.Info(fmt.Sprintf("iptables %s INPUT %s", opName, strings.Join(spec, " ")))
	}

	if device == "wg0" {
		cidr, err := network.ParseIPNet(seedPodNetwork)
		if err == nil && cidr.IsIPv4() {
			err = op4("nat", "PREROUTING", "--in-interface", device, "-d", constants.SeedPodNetworkMapped, "-j", "NETMAP", "--to", seedPodNetwork)
			if err != nil {
				return err
			}
			err = op4("nat", "POSTROUTING", "--out-interface", device, "-s", seedPodNetwork, "-j", "NETMAP", "--to", constants.SeedPodNetworkMapped)
			if err != nil {
				return err
			}
		}
	}

	if mode == "up" {
		dev, err := netlink.LinkByName(device)
		if err != nil {
			return err
		}
		// Check if the device is up, and set it up if not
		if dev.Attrs().Flags&net.FlagUp == 0 {
			if err := netlink.LinkSetUp(dev); err != nil {
				return fmt.Errorf("failed to set wg0 up: %w", err)
			}
		}
		for _, nw := range networks {
			_, ipnet, err := net.ParseCIDR(nw)
			if err != nil {
				return fmt.Errorf("parsing network %s failed: %s", nw, err)
			}
			if err := network.ReplaceRoute(log, ipnet, dev); err != nil {
				return err
			}
		}
	}
	return nil
}
