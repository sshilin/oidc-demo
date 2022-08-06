package oidc

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

const (
	ConfigFile = ".demo-cli-config"
)

type tokenJson struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	Expiry       int64  `json:"expiry"`
}

func SaveToken(token *oauth2.Token) error {
	conf, err := configPath()
	if err != nil {
		return err
	}

	f, err := os.Create(conf)
	if err != nil {
		return err
	}

	defer f.Close()

	tj := tokenJson{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IdToken:      token.Extra("id_token").(string),
		Expiry:       token.Expiry.Unix(),
	}

	data, err := json.MarshalIndent(tj, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func LoadToken() (*oauth2.Token, error) {
	conf, err := configPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(conf)
	if err != nil {
		if !os.IsExist(err) {
			return &oauth2.Token{}, nil
		}
		return nil, err
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	tj := &tokenJson{}

	err = json.Unmarshal(data, tj)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken:  tj.AccessToken,
		RefreshToken: tj.RefreshToken,
		Expiry:       time.Unix(tj.Expiry, 0),
	}

	raw := map[string]interface{}{
		"id_token": tj.IdToken,
	}

	return token.WithExtra(raw), nil
}

func DeleteToken() error {
	conf, err := configPath()
	if err != nil {
		return err
	}

	err = os.Remove(conf)
	if err != nil {
		return err
	}

	return nil
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ConfigFile), nil
}
