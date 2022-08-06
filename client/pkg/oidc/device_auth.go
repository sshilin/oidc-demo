package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	DefaultExpiresIn = time.Duration(60) * time.Second
	DefaultInterval  = time.Duration(5) * time.Second
)

var (
	ErrNetworkFailure    = errors.New("oidc: network")
	ErrMarshalingFailure = errors.New("oidc: marshaling")
	ErrTokenPollTimeout  = errors.New("oidc: token poll timeout")
	ErrTokenRequest      = errors.New("oidc: token request")
	ErrNotLoggedIn       = errors.New("oidc: not logged in")
)

type DeviceAuthFlow struct {
	ClientId  string
	WellKnown *WellKnownConfiguration
	Scope     []string
}

type DeviceAuthCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               uint   `json:"expires_in"`
	Interval                uint   `json:"interval"`
}

type WellKnownConfiguration struct {
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JwksUri                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	EndSessionEndpoint          string `json:"end_session_endpoint"`
}

func (c *WellKnownConfiguration) Endpoints() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  c.AuthorizationEndpoint,
		TokenURL: c.TokenEndpoint,
	}
}

func Discover(issuer string) (*WellKnownConfiguration, error) {
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkFailure, err)
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkFailure, err)
	}

	wellKnown := &WellKnownConfiguration{}

	err = json.Unmarshal(data, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMarshalingFailure, err)
	}

	return wellKnown, nil
}

func Client(issuer string, clientId string) (*http.Client, error) {
	ctx := context.Background()

	token, err := LoadToken()
	if err != nil {
		return nil, err
	}

	if token.AccessToken == "" {
		return nil, ErrNotLoggedIn
	}

	wellKnown, err := Discover(issuer)
	if err != nil {
		return nil, err
	}

	c := &oauth2.Config{
		ClientID: clientId,
		Endpoint: wellKnown.Endpoints(),
	}

	tokenSource := c.TokenSource(ctx, token)
	// Try to refresh access token outside of OAuth2 module.
	// So that it can be retrieved and saved here.
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenRequest, err)
	}

	if token != newToken {
		err = SaveToken(newToken)
		if err != nil {
			return nil, err
		}
	}

	return oauth2.NewClient(ctx, oauth2.StaticTokenSource(newToken)), nil
}

func (c *DeviceAuthFlow) RetrieveAuthCode() (*DeviceAuthCode, error) {
	values := url.Values{
		"client_id": {c.ClientId},
		"scope":     c.Scope,
	}.Encode()

	data, err := doHttpPost(c.WellKnown.DeviceAuthorizationEndpoint, values)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkFailure, err)
	}

	deviceAuth := &DeviceAuthCode{}

	err = json.Unmarshal(data, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMarshalingFailure, err)
	}

	return deviceAuth, nil
}

func (c *DeviceAuthFlow) RetrieveToken(deviceAuth *DeviceAuthCode) (*oauth2.Token, error) {
	expiresIn := DefaultExpiresIn
	if deviceAuth.ExpiresIn > 0 {
		expiresIn = time.Duration(deviceAuth.ExpiresIn) * time.Second
	}

	timeout := time.After(expiresIn)

	interval := DefaultInterval
	if deviceAuth.Interval > 0 {
		interval = time.Duration(deviceAuth.Interval) * time.Second
	}

	ticker := time.NewTicker(interval)

	values := url.Values{
		"client_id":   {c.ClientId},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceAuth.DeviceCode},
	}.Encode()

	for {
		select {
		case <-ticker.C:
			data, err := doHttpPost(c.WellKnown.TokenEndpoint, values)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrNetworkFailure, err)
			}

			var respJson struct {
				AccessToken      string `json:"access_token"`
				RefreshToken     string `json:"refresh_token"`
				IdToken          string `json:"id_token"`
				ExpiresIn        int    `json:"expires_in"`
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}

			err = json.Unmarshal(data, &respJson)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMarshalingFailure, err)
			}

			if respJson.Error == "" {
				token := &oauth2.Token{
					AccessToken:  respJson.AccessToken,
					RefreshToken: respJson.RefreshToken,
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Duration(respJson.ExpiresIn) * time.Second),
				}

				raw := map[string]interface{}{
					"id_token": respJson.IdToken,
				}

				return token.WithExtra(raw), nil
			} else if respJson.Error == "access_denied" || respJson.Error == "expired_token" {
				return nil, fmt.Errorf("%w: %v", ErrTokenRequest, respJson.Error)
			} else if respJson.Error == "slow_down" {
				interval *= 2
				ticker.Reset(interval)
			}
		case <-timeout:
			return nil, ErrTokenPollTimeout
		}
	}
}

func (c *DeviceAuthFlow) EndSession() error {
	token, err := LoadToken()
	if err != nil {
		return err
	}

	if token.RefreshToken != "" {
		values := url.Values{
			"client_id":     {c.ClientId},
			"refresh_token": {token.RefreshToken},
		}.Encode()

		_, err = doHttpPost(c.WellKnown.EndSessionEndpoint, values)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNetworkFailure, err)
		}

		err = DeleteToken()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNetworkFailure, err)
		}
	}

	return nil
}

func doHttpPost(url string, values string) ([]byte, error) {
	resp, err := http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(values))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}
