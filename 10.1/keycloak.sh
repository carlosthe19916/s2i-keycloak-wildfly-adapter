#!/bin/bash -e
WAR_NAME=ROOT

if [ -n "$KEYCLOAK_REALM" ] && [ -n "$KEYCLOAK_RESOURCE" ] && [ -n "$KEYCLOAK_AUTH_SERVER_URL" ] && [ -n "$KEYCLOAK_SECURE_DEPLOYMENT" ]
then
  if [[ $KEYCLOAK_SECURE_DEPLOYMENT == *.war ]]; 
  then
    WAR_NAME=$KEYCLOAK_SECURE_DEPLOYMENT
  else
    WAR_NAME=$KEYCLOAK_SECURE_DEPLOYMENT.war
  fi
  # Add realm subsystem
  /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:add\(auth-server-url=$KEYCLOAK_AUTH_SERVER_URL\)
  
  if [ -n "$KEYCLOAK_PUBLIC_KEY" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute\(name=public-key,value=$KEYCLOAK_PUBLIC_KEY\)
  fi
  if [ -n "$KEYCLOAK_SSL_REQUIRED" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute\(ssl-required,value=$KEYCLOAK_SSL_REQUIRED\)
  fi

  # Add secure deployment
  if [ -n "$KEYCLOAK_RESOURCE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(resource=$KEYCLOAK_RESOURCE\)
  fi
  if [ -n "$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(use-resource-role-mappings=$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS\)
  fi
  if [ -n "$KEYCLOAK_ENABLE_CORS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(enable-cors=$KEYCLOAK_ENABLE_CORS\)
  fi
  if [ -n "$KEYCLOAK_CORS_MAX_AGE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(cors-max-age=$KEYCLOAK_CORS_MAX_AGE\)
  fi
  if [ -n "$KEYCLOAK_CORS_ALLOWED_METHODS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(cors-allowed-methods=$KEYCLOAK_CORS_ALLOWED_METHODS\)
  fi
  if [ -n "$KEYCLOAK_BEARER_ONLY" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(bearer-only=$KEYCLOAK_BEARER_ONLY\)
  fi
  if [ -n "$KEYCLOAK_ENABLE_BASIC_AUTH" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(enable-basic-auth=$KEYCLOAK_ENABLE_BASIC_AUTH\)
  fi
  if [ -n "$KEYCLOAK_EXPOSE_TOKEN" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(expose-token=$KEYCLOAK_EXPOSE_TOKEN\)
  fi
  if [ -n "$KEYCLOAK_CREDENTIAL" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME/credential=secret:add\(value=$KEYCLOAK_CREDENTIAL\)
  fi

  if [ -n "$KEYCLOAK_CONNECTION_POOL_SIZE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(connection-pool-size=$KEYCLOAK_CONNECTION_POOL_SIZE\)
  fi
  if [ -n "$KEYCLOAK_DISABLE_TRUST_MANAGER" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(disable-trust-manager=$KEYCLOAK_DISABLE_TRUST_MANAGER\)
  fi
  if [ -n "$KEYCLOAK_ALLOW_ANY_HOSTNAME" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(allow-any-hostname=$KEYCLOAK_ALLOW_ANY_HOSTNAME\)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(truststore=$KEYCLOAK_TRUSTSTORE\)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE_PASSWORD" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(truststore-password=$KEYCLOAK_TRUSTSTORE_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(client-keystore=$KEYCLOAK_CLIENT_KEYSTORE\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(client-keystore-password=$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEY_PASSWORD" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(client-key-password=$KEYCLOAK_CLIENT_KEY_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(token-minimun-time-to-live=$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE\)
  fi
  if [ -n "$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(min-time-between-jwks-requests=$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS\)
  fi
  if [ -n "$KEYCLOAK_PUBLIC_KEY_CACHE_TTL" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deploymeny=$WAR_NAME:add\(public-key-cache-ttl=$KEYCLOAK_PUBLIC_KEY_CACHE_TTL\)
  fi
fi
