package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sshilin/oidc-demo/client/pkg/oidc"
)

var logoutCmd = &cobra.Command{
	Use: "logout",
	Run: func(cmd *cobra.Command, args []string) {
		wellKnown, err := oidc.Discover(Issuer)
		failNow(cmd.Name(), err)

		flow := &oidc.DeviceAuthFlow{
			ClientId:  ClientID,
			Scope:     []string{"openid"},
			WellKnown: wellKnown,
		}

		failNow(cmd.Name(), flow.EndSession())

		fmt.Println("logged out")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
