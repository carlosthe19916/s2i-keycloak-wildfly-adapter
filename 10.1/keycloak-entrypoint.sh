#!/bin/bash

if [ -n "$HTTPS_NAME" ] && [ -n "$HTTPS_PASSWORD" ] && [ -n "$HTTPS_KEYSTORE" ]
then
    # Add realm subsystem
    echo "subsystem=keycloak/realm"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/core-service=management/security-realm=UndertowRealm:add\(\)
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/core-service=management/security-realm=UndertowRealm/server-identity=ssl:add\(keystore-path=$HTTPS_KEYSTORE,keystore-relative-to=jboss.server.config.dir,keystore-password=$HTTPS_PASSWORD\)
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=undertow/server=default-server/https-listener=$HTTPS_NAME:add\(socket-binding=https,security-realm=UndertowRealm\)
fi

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
  echo "subsystem=keycloak/realm"
  /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:add\(auth-server-url=$KEYCLOAK_AUTH_SERVER_URL\)
  
  if [ -n "$KEYCLOAK_PUBLIC_KEY" ]; then
    echo "public-key"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute\(name=public-key,value=$KEYCLOAK_PUBLIC_KEY\)
  fi
  if [ -n "$KEYCLOAK_SSL_REQUIRED" ]; then
    echo "ssl-required"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/realm=$KEYCLOAK_REALM:write-attribute\(name=ssl-required,value=$KEYCLOAK_SSL_REQUIRED\)
  fi

  # Add secure deployment
  echo "subsystem=keycloak/secure-deployment"
  /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:add\(realm=$KEYCLOAK_REALM\)
  
  if [ -n "$KEYCLOAK_RESOURCE" ]; then
    echo "resource"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=resource,value=$KEYCLOAK_RESOURCE\)
  fi
  if [ -n "$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS" ]; then
    echo "use-resource-role-mappings"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=use-resource-role-mappings,value=$KEYCLOAK_USE_RESOURCE_ROLE_MAPPINGS\)
  fi
  if [ -n "$KEYCLOAK_ENABLE_CORS" ]; then
    echo "enable-cors"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=enable-cors,value=$KEYCLOAK_ENABLE_CORS\)
  fi
  if [ -n "$KEYCLOAK_CORS_MAX_AGE" ]; then
    echo "cors-max-age"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=cors-max-age,value=$KEYCLOAK_CORS_MAX_AGE\)
  fi
  if [ -n "$KEYCLOAK_CORS_ALLOWED_METHODS" ]; then
    echo "cors-allowed-metthods"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=cors-allowed-methods,value=$KEYCLOAK_CORS_ALLOWED_METHODS\)
  fi
  if [ -n "$KEYCLOAK_BEARER_ONLY" ]; then
    echo "bearer-only"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=bearer-only,value=$KEYCLOAK_BEARER_ONLY\)
  fi
  if [ -n "$KEYCLOAK_ENABLE_BASIC_AUTH" ]; then
    echo "enable-basic-auth"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=enable-basic-auth,value=$KEYCLOAK_ENABLE_BASIC_AUTH\)
  fi
  if [ -n "$KEYCLOAK_EXPOSE_TOKEN" ]; then
    echo "expose-token"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=expose-token,value=$KEYCLOAK_EXPOSE_TOKEN\)
  fi
  if [ -n "$KEYCLOAK_CREDENTIAL" ]; then
    echo "credential"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME/credential=secret:add\(value=$KEYCLOAK_CREDENTIAL\)
  fi

  if [ -n "$KEYCLOAK_CONNECTION_POOL_SIZE" ]; then
    echo "connection-pool-size"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=connection-pool-size,value=$KEYCLOAK_CONNECTION_POOL_SIZE\)
  fi
  if [ -n "$KEYCLOAK_DISABLE_TRUST_MANAGER" ]; then
    echo "disable-trust-manager"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=disable-trust-manager,value=$KEYCLOAK_DISABLE_TRUST_MANAGER\)
  fi
  if [ -n "$KEYCLOAK_ALLOW_ANY_HOSTNAME" ]; then
    echo "allow-any-hostname"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=allow-any-hostname,value=$KEYCLOAK_ALLOW_ANY_HOSTNAME\)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE" ]; then
    echo "truststore"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=truststore,value=$KEYCLOAK_TRUSTSTORE\)
  fi
  if [ -n "$KEYCLOAK_TRUSTSTORE_PASSWORD" ]; then
    echo "truststore-password"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=truststore-password,value=$KEYCLOAK_TRUSTSTORE_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE" ]; then
    echo "client-keystore"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=client-keystore,value=$KEYCLOAK_CLIENT_KEYSTORE\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD" ]; then
    echo "client-keystore-password"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=client-keystore-password,value=$KEYCLOAK_CLIENT_KEYSTORE_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_CLIENT_KEY_PASSWORD" ]; then
    echo "client-key-password"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=client-key-password,value=$KEYCLOAK_CLIENT_KEY_PASSWORD\)
  fi
  if [ -n "$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE" ]; then
    echo "token-minimun-time-to-live"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=token-minimun-time-to-live,value=$KEYCLOAK_TOKEN_MINIMUN_TIME_TO_LIVE\)
  fi
  if [ -n "$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS" ]; then
    echo "min-time-between-jwks-requests"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=min-time-between-jwks-requests,value=$KEYCLOAK_MIN_TIME_BETWEEN_JWKS_REQUESTS\)
  fi
  if [ -n "$KEYCLOAK_PUBLIC_KEY_CACHE_TTL" ]; then
    echo "public-key-cache-ttl"
    /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME:write-attribute\(name=public-key-cache-ttl,value=$KEYCLOAK_PUBLIC_KEY_CACHE_TTL\)
  fi

  # removing history
  rm -rf /wildfly/standalone/configuration/standalone_xml_history/current/*
fi

# Client registration
if [ -n "$KEYCLOAK_INITIAL_ACCESS_TOKEN" ] && [ -n "$KEYCLOAK_AUTH_SERVER_URL" ] && [ -n "$KEYCLOAK_REALM" ] && [ -n "$KEYCLOAK_RESOURCE" ]
then
  echo "trying to configure keycloak-cli"
  /wildfly/bin/kcreg.sh config initial-token $KEYCLOAK_INITIAL_ACCESS_TOKEN --server $KEYCLOAK_AUTH_SERVER_URL --realm $KEYCLOAK_REALM

  echo "trying to create cli"
  /wildfly/bin/kcreg.sh create -s clientId=$KEYCLOAK_RESOURCE -s protocol=openid-connect -s rootUrl=/$KEYCLOAK_RESOURCE
  
  if [ -n "$KEYCLOAK_BEARER_ONLY" ]; then
    echo "updating cli to bearer-only"
    /wildfly/bin/kcreg.sh update $KEYCLOAK_RESOURCE -s bearerOnly=$KEYCLOAK_BEARER_ONLY
  fi
fi

exec "$@"
