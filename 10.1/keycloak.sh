#!/bin/bash -e
if [ -n "$KEYCLOAK_REALM" ]
then
  /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM
  
  if [ -n "$KEYCLOAK_PUBLIC_KEY" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute(name=public-key,value=$KEYCLOAK_PUBLIC_KEY)
  fi
  if [ -n "$KEYCLOAK_AUTH_SERVER_URL" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute(name=auth-server-url,value=$KEYCLOAK_AUTH_SERVER_URL)
  fi
  if [ -n "$KEYCLOAK_SSL_REQUIRED" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute(ssl-required,value=$KEYCLOAK_SSL_REQUIRED)
  fi
fi

if [ -n "$KEYCLOAK_SECURE_DEPLOYMENT" ]
then
  if [ -n "$KEYCLOAK_RESOURCE" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(resource=$KEYCLOAK_RESOURCE)
  fi
  if [ -n "$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(use-resource-role-mappings=$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS)
  fi
  if [ -n "$KEYCLOAK_ENABLE_CORS" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(enable-cors=$KEYCLOAK_ENABLE_CORS)
  fi
  if [ -n "$KEYCLOAK_CORS_MAX_AGE" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(cors-max-age=$KEYCLOAK_CORS_MAX_AGE)
  fi
  if [ -n "$KEYCLOAK_CORS_ALLOWED_METHODS" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(cors-allowed-methods=$KEYCLOAK_CORS_ALLOWED_METHODS)
  fi
  if [ -n "$KEYCLOAK_BEARER_ONLY" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(bearer-only=$KEYCLOAK_BEARER_ONLY)
  fi
  if [ -n "$KEYCLOAK_ENABLE_BASIC_AUTH" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(enable-basic-auth=$KEYCLOAK_ENABLE_BASIC_AUTH)
  fi
  if [ -n "$KEYCLOAK_EXPOSE_TOKEN" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(expose-token=$KEYCLOAK_EXPOSE_TOKEN)
  fi
  if [ -n "$KEYCLOAK_CREDENTIAL" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war/credential=secret:add(value=$KEYCLOAK_CREDENTIAL)
  fi

  if [ -n "$KEYCLOAK_CONNECTION_POOL_SIZE" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(connection-pool-size=$KEYCLOAK_CONNECTION_POOL_SIZE)
  fi
  if [ -n "$KEYCLOAK_DISABLE_TRUST_MANAGER" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(disable-trust-manager=$KEYCLOAK_DISABLE_TRUST_MANAGER)
  fi
  if [ -n "$KEYCLOAK_ALLOW_ANY_HOSTNAME" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(allow-any-hostname=$KEYCLOAK_ALLOW_ANY_HOSTNAME)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(truststore=$KEYCLOAK_TRUSTSTORE)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE_PASSWORD" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(truststore-password=$KEYCLOAK_TRUSTSTORE_PASSWORD)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(client-keystore=$KEYCLOAK_CLIENT_KEYSTORE)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(client-keystore-password=$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEY_PASSWORD" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(client-key-password=$KEYCLOAK_CLIENT_KEY_PASSWORD)
  fi
  if [ -n "$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(token-minimun-time-to-live=$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE)
  fi
  if [ -n "$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(min-time-between-jwks-requests=$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS)
  fi
  if [ -n "$KEYCLOAK_PUBLIC_KEY_CACHE_TTL" ] then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$KEYCLOAK_SECURE_DEPLOYMENT.war:add(public-key-cache-ttl=$KEYCLOAK_PUBLIC_KEY_CACHE_TTL)
  fi
fi
