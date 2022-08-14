#!/bin/sh

export PATH=$PATH:/opt/keycloak/bin

kcadm.sh config credentials --server $KEYCLOAK_SERVER --realm master --user admin --password admin

# Create realm
kcadm.sh create realms -f - << EOF
{
    "realm": "demo",
    "enabled": true
}
EOF

# Create a client with Device Authorization Flow
kcadm.sh create clients -r demo -f - << EOF
{
	"clientId": "demo-cli",
	"publicClient": true,
	"directAccessGrantsEnabled": false,
	"standardFlowEnabled": false,
	"attributes": {"oauth2.device.authorization.grant.enabled": "true"}
}
EOF

# Create test user
kcadm.sh create users -r demo -s username=user1 -s enabled=true
kcadm.sh set-password -r demo --username user1 --new-password 1234