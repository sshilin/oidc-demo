package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

type verifier struct {
	jwks *keyfunc.JWKS
}

func NewVerifier(jwksUrl string, client *http.Client) (*verifier, error) {
	jwks, err := keyfunc.Get(jwksUrl, keyfunc.Options{Client: client})
	if err != nil {
		return nil, err
	}

	return &verifier{jwks}, nil
}

func (jwks *verifier) Verify(rawToken string) bool {
	idToken, err := jwt.Parse(rawToken, jwks.jwks.Keyfunc)
	if err != nil {
		return false
	}

	return idToken.Valid
}

func (jwks *verifier) Subject(token *oauth2.Token) (string, error) {
	rawToken, err := extractIdToken(token)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(strings.Split(rawToken, ".")[1])
	if err != nil {
		return "", err
	}

	var claims struct {
		PreferedUsername string `json:"preferred_username"`
	}

	if err = json.Unmarshal(data, &claims); err != nil {
		return "", err
	}

	return claims.PreferedUsername, nil
}

func extractIdToken(token *oauth2.Token) (string, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id token")
	}

	return idToken, nil
}
