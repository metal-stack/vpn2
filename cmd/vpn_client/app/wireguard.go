package app

import (
	"context"
	"fmt"

	"github.com/gardener/vpn2/pkg/config"
	"github.com/gardener/vpn2/pkg/utils"
	"github.com/gardener/vpn2/pkg/wireguard"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

func wireguardCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "wireguard",
		Short: "wireguard",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := utils.InitRun(cmd, Name)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			return runWireguard(ctx, log)
		},
	}
	return cmd
}

func runWireguard(ctx context.Context, log logr.Logger) error {
	cfg, err := config.GetVPNClientConfig()
	if err != nil {
		return fmt.Errorf("could not parse environment")
	}

	log.Info("starting wireguard client", "cfg", cfg)
	return wireguard.StartClient(ctx, log, cfg)
}
