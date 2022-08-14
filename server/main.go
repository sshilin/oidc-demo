package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func initJwks(issuer string) (*keyfunc.JWKS, error) {
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var respJson struct {
		JwksUri string `json:"jwks_uri"`
	}

	err = json.Unmarshal(data, &respJson)
	if err != nil {
		return nil, err
	}

	return keyfunc.Get(respJson.JwksUri, keyfunc.Options{})
}

func withAuth(jwks *keyfunc.JWKS, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.Fields(r.Header.Get("Authorization"))

		if len(auth) != 2 || auth[0] != "Bearer" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		rawToken := auth[1]

		_, err := jwt.Parse(rawToken, jwks.Keyfunc)
		if err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func headers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := map[string]string{}
		for k, v := range r.Header {
			h[k] = strings.Join(v, ",")
		}

		data, _ := json.MarshalIndent(h, "", "  ")
		w.Header().Add("Content-type", "application/json")
		w.Write([]byte(data))
	}
}

func main() {
	jwks, err := initJwks(os.Getenv("IAM_URL"))
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/headers", withAuth(jwks, headers()))
	log.Fatal(http.ListenAndServe(":80", nil))
}
