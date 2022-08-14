## oidc-demo

Oidc-demo shows OAuth 2.0 Device Authorization Grant type built with Keycloak and Go CLI client.

The `client` initiates the login flow and instructs the user with a user code and an authentication URL to be opened on a web-capable device. Once the user authenticates itself, Kyacloak allows the `client` to exchange its device code to tokens. Now the `client` can send authorized http requests to the `server`. The `client` and `server` verifies RS256-signed tokens using JSON Web Key Set (JWKS) retrieved from Keycloak.

## usage

1. Start Keycloak and Resource Server
```
docker compose up --build -d
```

2. Use CLI client to sign in and send authorized `GET headers` requests to Resource Server
```
go run . login
go run . headers
go run . logout
```
