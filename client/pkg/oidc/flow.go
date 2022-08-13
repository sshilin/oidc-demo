package oidc

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	DefaultTimeout  = time.Duration(60) * time.Second
	DefaultInterval = time.Duration(5) * time.Second
)

type DeviceAuthFlow struct {
	ClientId  string
	Scope     []string
	WellKnown *WellKnownConfiguration
	Client    *http.Client
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

func Discover(issuer string, client *http.Client) (*WellKnownConfiguration, error) {
	data, err := doHttpGet(client, issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}

	err = checkErrResponse(data)
	if err != nil {
		return nil, err
	}

	var conf *WellKnownConfiguration

	err = json.Unmarshal(data, &conf)
	if err != nil {
		return nil, err
	}

	return conf, nil
}

func (f *DeviceAuthFlow) RetrieveAuthCode() (*DeviceAuthCode, error) {
	values := url.Values{
		"client_id": {f.ClientId},
		"scope":     f.Scope,
	}.Encode()

	data, err := doHttpPost(f.Client, f.WellKnown.DeviceAuthorizationEndpoint, values)
	if err != nil {
		return nil, err
	}

	err = checkErrResponse(data)
	if err != nil {
		return nil, err
	}

	var dac *DeviceAuthCode

	err = json.Unmarshal(data, &dac)
	if err != nil {
		return nil, err
	}

	return dac, nil
}

func (f *DeviceAuthFlow) RetrieveToken(deviceAuth *DeviceAuthCode) (*oauth2.Token, error) {
	var timeout = DefaultTimeout
	if deviceAuth.ExpiresIn > 0 {
		timeout = time.Duration(deviceAuth.ExpiresIn) * time.Second
	}

	var interval = DefaultInterval
	if deviceAuth.Interval > 0 {
		interval = time.Duration(deviceAuth.Interval) * time.Second
	}

	return f.poll(interval, timeout, deviceAuth.DeviceCode)
}

func (f *DeviceAuthFlow) poll(interval time.Duration, timeout time.Duration, deviceCode string) (*oauth2.Token, error) {
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			token, err := f.tryExchange(deviceCode)
			if err != nil {
				switch err.Error() {
				case "authorization_pending":
					continue
				case "slow_down":
					interval *= 2
					ticker.Reset(interval)
				default:
					return nil, err
				}
			} else {
				return token, nil
			}
		case <-time.After(timeout):
			return nil, errors.New("poll timeout")
		}
	}
}

func (f *DeviceAuthFlow) tryExchange(deviceCode string) (*oauth2.Token, error) {
	values := url.Values{
		"client_id":   {f.ClientId},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	}.Encode()

	data, err := doHttpPost(f.Client, f.WellKnown.TokenEndpoint, values)
	if err != nil {
		return nil, err
	}

	err = checkErrResponse(data)
	if err != nil {
		return nil, err
	}

	var respJson struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IdToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	err = json.Unmarshal(data, &respJson)
	if err != nil {
		return nil, err
	}

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
}

func (f *DeviceAuthFlow) EndSession(token *oauth2.Token) error {
	if token.RefreshToken == "" {
		return nil
	}

	values := url.Values{
		"client_id":     {f.ClientId},
		"refresh_token": {token.RefreshToken},
	}.Encode()

	_, err := doHttpPost(f.Client, f.WellKnown.EndSessionEndpoint, values)
	if err != nil {
		return err
	}

	return nil
}

func checkErrResponse(data []byte) error {
	var respJson struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}

	err := json.Unmarshal(data, &respJson)
	if err != nil {
		return err
	}

	if respJson.Error != "" {
		return errors.New(respJson.Error)
	}

	return nil
}

func doHttpGet(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
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

func doHttpPost(client *http.Client, url string, values string) ([]byte, error) {
	resp, err := client.Post(url, "application/x-www-form-urlencoded", strings.NewReader(values))
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
