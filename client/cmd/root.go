package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	Issuer   = "http://localhost:8080/realms/demo"
	Resource = "http://localhost:9090"
	ClientID = "demo-cli"
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

func failNow(cmd string, err error) {
	if err != nil {
		fmt.Printf("ERROR: '%s' has failed: %v\n", cmd, err)
		os.Exit(1)
	}
}
