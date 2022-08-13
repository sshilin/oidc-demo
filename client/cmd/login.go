package cmd

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sshilin/oidc-demo/client/pkg/config"
	"github.com/sshilin/oidc-demo/client/pkg/oidc"
)

var loginCmd = &cobra.Command{
	Use: "login",
	Run: func(cmd *cobra.Command, args []string) {
		httpClient := http.DefaultClient

		wellKnown, err := oidc.Discover(Issuer, http.DefaultClient)
		cobra.CheckErr(err)

		verifier, err := oidc.NewVerifier(wellKnown.JwksUri, httpClient)
		cobra.CheckErr(err)

		flow := &oidc.DeviceAuthFlow{
			ClientId:  ClientId,
			Scope:     []string{"openid"},
			WellKnown: wellKnown,
			Client:    http.DefaultClient,
		}

		code, err := flow.RetrieveAuthCode()
		cobra.CheckErr(err)

		fmt.Printf("To sign in, open %s in the browser and enter the code: %s\n", code.VerificationUri, code.UserCode)

		token, err := flow.RetrieveToken(code)
		cobra.CheckErr(err)

		sub, err := verifier.Subject(token)
		cobra.CheckErr(err)

		viper.Set(config.KeyAccessToken, token.AccessToken)
		viper.Set(config.KeyRefreshToken, token.RefreshToken)
		viper.Set(config.KeyIdToken, token.Extra("id_token").(string))
		viper.Set(config.KeyExpiry, token.Expiry.Unix())

		err = config.WriteConfig()
		cobra.CheckErr(err)

		fmt.Println("Signed in:", sub)
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
