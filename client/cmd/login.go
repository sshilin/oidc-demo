package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sshilin/oidc-demo/client/pkg/oidc"
)

var loginCmd = &cobra.Command{
	Use: "login",
	Run: func(cmd *cobra.Command, args []string) {
		wellKnown, err := oidc.Discover(Issuer)
		failNow(cmd.Name(), err)

		flow := &oidc.DeviceAuthFlow{
			ClientId:  ClientID,
			Scope:     []string{"openid"},
			WellKnown: wellKnown,
		}

		code, err := flow.RetrieveAuthCode()
		failNow(cmd.Name(), err)

		fmt.Printf("\n\tTo sign in, open %s and enter the code: %s\n\n", code.VerificationUri, code.UserCode)

		token, err := flow.RetrieveToken(code)
		failNow(cmd.Name(), err)

		err = oidc.SaveToken(token)
		failNow(cmd.Name(), err)
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
