package config

import (
	"os"

	"github.com/spf13/viper"
)

const (
	KeyAccessToken  = "access-token"
	KeyRefreshToken = "refresh-token"
	KeyIdToken      = "id-token"
	KeyExpiry       = "expiry"
)

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	viper.SetConfigName(".demo-config")
	viper.AddConfigPath(home)
	viper.SetConfigType("json")
}

func ReadConfig() error {
	return viper.ReadInConfig()
}

func WriteConfig() error {
	if err := viper.WriteConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			err = viper.SafeWriteConfig()
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}
