package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

const (
	Issuer   = "http://localhost:8080/realms/demo"
	Resource = "http://localhost:9090"
	ClientId = "demo-cli"
)

var rootCmd = &cobra.Command{
	Use:   "client",
	Short: "OIDC Demo client",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
