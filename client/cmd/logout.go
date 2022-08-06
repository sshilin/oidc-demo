package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use: "logout",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("logout called")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
