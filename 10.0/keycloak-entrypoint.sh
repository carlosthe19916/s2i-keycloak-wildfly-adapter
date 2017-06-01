#!/bin/bash

WAR_NAME=ROOT

if [ -n "$KEYCLOAK_REALM" ] && [ -n "$KEYCLOAK_RESOURCE" ] && [ -n "$KEYCLOAK_AUTH_SERVER_URL" ] && [ -n "$KEYCLOAK_SECURE_DEPLOYMENT" ]
then

  # Remove last slash from keycloak
  export KEYCLOAK_AUTH_SERVER_URL=${KEYCLOAK_AUTH_SERVER_URL%/}

  # Check war name
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
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute\(name=ssl-required,value=$KEYCLOAK_SSL_REQUIRED\)
  fi

  # Add secure deployment
  /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:add\(realm=$KEYCLOAK_REALM\)
  
  if [ -n "$KEYCLOAK_RESOURCE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=resource,value=$KEYCLOAK_RESOURCE\)
  fi
  if [ -n "$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=use-resource-role-mappings,value=$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS\)
  fi
  if [ -n "$KEYCLOAK_ENABLE_CORS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=enable-cors,value=$KEYCLOAK_ENABLE_CORS\)
  fi
  if [ -n "$KEYCLOAK_CORS_MAX_AGE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=cors-max-age,value=$KEYCLOAK_CORS_MAX_AGE\)
  fi
  if [ -n "$KEYCLOAK_CORS_ALLOWED_METHODS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=cors-allowed-methods,value=$KEYCLOAK_CORS_ALLOWED_METHODS\)
  fi
  if [ -n "$KEYCLOAK_BEARER_ONLY" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=bearer-only,value=$KEYCLOAK_BEARER_ONLY\)
  fi
  if [ -n "$KEYCLOAK_ENABLE_BASIC_AUTH" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=enable-basic-auth,value=$KEYCLOAK_ENABLE_BASIC_AUTH\)
  fi
  if [ -n "$KEYCLOAK_EXPOSE_TOKEN" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=expose-token,value=$KEYCLOAK_EXPOSE_TOKEN\)
  fi
  if [ -n "$KEYCLOAK_CREDENTIAL" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME/credential=secret:add\(value=$KEYCLOAK_CREDENTIAL\)
  fi

  if [ -n "$KEYCLOAK_CONNECTION_POOL_SIZE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=connection-pool-size,value=$KEYCLOAK_CONNECTION_POOL_SIZE\)
  fi
  if [ -n "$KEYCLOAK_DISABLE_TRUST_MANAGER" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=disable-trust-manager,value=$KEYCLOAK_DISABLE_TRUST_MANAGER\)
  fi
  if [ -n "$KEYCLOAK_ALLOW_ANY_HOSTNAME" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=allow-any-hostname,value=$KEYCLOAK_ALLOW_ANY_HOSTNAME\)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=truststore,value=$KEYCLOAK_TRUSTSTORE\)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE_PASSWORD" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=truststore-password,value=$KEYCLOAK_TRUSTSTORE_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=client-keystore,value=$KEYCLOAK_CLIENT_KEYSTORE\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=client-keystore-password,value=$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEY_PASSWORD" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=client-key-password,value=$KEYCLOAK_CLIENT_KEY_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=token-minimun-time-to-live,value=$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE\)
  fi
  if [ -n "$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=min-time-between-jwks-requests,value=$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS\)
  fi
  if [ -n "$KEYCLOAK_PUBLIC_KEY_CACHE_TTL" ]; then
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=public-key-cache-ttl,value=$KEYCLOAK_PUBLIC_KEY_CACHE_TTL\)
  fi
fi

rm -rf /wildfly/standalone/configuration/standalone_xml_history/current/*

# Client registration
if [ -n "$KEYCLOAK_INITIAL_ACCESS_TOKEN" ] && [ -n "$KEYCLOAK_AUTH_SERVER_URL" ] && [ -n "$KEYCLOAK_REALM" ] && [ -n "$KEYCLOAK_RESOURCE" ]
then
  /wildfly/bin/kcreg.sh config initial-token $KEYCLOAK_INITIAL_ACCESS_TOKEN --server $KEYCLOAK_AUTH_SERVER_URL --realm $KEYCLOAK_REALM
  /wildfly/bin/kcreg.sh create -s clientId=$KEYCLOAK_RESOURCE -s protocol=openid-connect -s rootUrl=/$KEYCLOAK_RESOURCE
  
  if [ -n "$KEYCLOAK_BEARER_ONLY" ]; then
    /wildfly/bin/kcreg.sh update $KEYCLOAK_RESOURCE -s bearerOnly=$KEYCLOAK_BEARER_ONLY
  fi

fi

exec "$@"
