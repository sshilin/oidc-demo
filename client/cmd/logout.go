package cmd

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sshilin/oidc-demo/client/pkg/config"
	"github.com/sshilin/oidc-demo/client/pkg/oidc"
	"golang.org/x/oauth2"
)

var logoutCmd = &cobra.Command{
	Use: "logout",
	Run: func(cmd *cobra.Command, args []string) {
		wellKnown, err := oidc.Discover(Issuer, http.DefaultClient)
		cobra.CheckErr(err)

		flow := &oidc.DeviceAuthFlow{
			ClientId:  ClientId,
			Scope:     []string{"openid"},
			WellKnown: wellKnown,
			Client:    http.DefaultClient,
		}

		err = flow.EndSession(&oauth2.Token{
			RefreshToken: viper.GetString(config.KeyRefreshToken),
		})
		cobra.CheckErr(err)

		fmt.Println("logged out")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
