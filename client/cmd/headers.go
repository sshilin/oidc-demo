package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sshilin/oidc-demo/client/pkg/config"
	"github.com/sshilin/oidc-demo/client/pkg/oidc"
	"golang.org/x/oauth2"
)

var headersCmd = &cobra.Command{
	Use:   "headers",
	Short: "Echo HTTP request headers the client sent to the server",
	Run: func(cmd *cobra.Command, args []string) {
		httpClient := http.DefaultClient

		err := config.ReadConfig()
		cobra.CheckErr(err)

		wellKnown, err := oidc.Discover(Issuer, http.DefaultClient)
		cobra.CheckErr(err)

		verifier, err := oidc.NewVerifier(wellKnown.JwksUri, httpClient)
		cobra.CheckErr(err)

		if !verifier.Verify(viper.GetString(config.KeyIdToken)) {
			cobra.CheckErr("Not logged in")
		}

		conf := oidc.Config{
			ClientId:  ClientId,
			WellKnown: wellKnown,
		}

		token, err := conf.RefreshToken(context.Background(), &oauth2.Token{
			AccessToken:  viper.GetString(config.KeyAccessToken),
			RefreshToken: viper.GetString(config.KeyRefreshToken),
			Expiry:       time.Unix(viper.GetInt64(config.KeyExpiry), 0),
		})
		cobra.CheckErr(err)

		viper.Set(config.KeyAccessToken, token.AccessToken)
		viper.Set(config.KeyRefreshToken, token.RefreshToken)
		viper.Set(config.KeyExpiry, token.Expiry.Unix())

		err = config.WriteConfig()
		cobra.CheckErr(err)

		client, err := conf.NewClient(context.Background(), token)
		cobra.CheckErr(err)

		resp, err := client.Get(Resource + "/headers")
		cobra.CheckErr(err)

		defer resp.Body.Close()

		data, err := ioutil.ReadAll(resp.Body)
		cobra.CheckErr(err)

		fmt.Println(string(data))
	},
}

func init() {
	rootCmd.AddCommand(headersCmd)
}
