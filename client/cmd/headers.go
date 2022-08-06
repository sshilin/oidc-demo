package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
	"github.com/sshilin/oidc-demo/client/pkg/oidc"
)

var headersCmd = &cobra.Command{
	Use:   "headers",
	Short: "Echo HTTP request headers the client sent to the server",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := oidc.Client(Issuer, ClientID)
		failNow(cmd.Name(), err)

		resp, err := client.Get(Resource + "/headers")
		failNow(cmd.Name(), err)

		defer resp.Body.Close()

		data, err := ioutil.ReadAll(resp.Body)
		failNow(cmd.Name(), err)

		fmt.Println(string(data))
	},
}

func init() {
	rootCmd.AddCommand(headersCmd)
}
