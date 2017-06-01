FROM openshift/wildfly-101-centos7

ENV KEYCLOAK_VERSION 3.1.0.Final

# Add s2i wildfly customizations
ADD ./contrib/wfbin/standalone.conf /wildfly/bin/standalone.conf
ADD ./contrib/wfcfg/standalone.xml /wildfly/standalone/configuration/standalone.xml

# install keycloak adapter
USER 1001
WORKDIR /wildfly
RUN curl -L https://downloads.jboss.org/keycloak/$KEYCLOAK_VERSION/adapters/keycloak-oidc/keycloak-wildfly-adapter-dist-$KEYCLOAK_VERSION.tar.gz | tar zx

# Standalone.xml modifications.
RUN sed -i -e 's/<extensions>/&\n        <extension module="org.keycloak.keycloak-adapter-subsystem"\/>/' /wildfly/standalone/configuration/standalone.xml && \
    sed -i -e 's/<profile>/&\n        <subsystem xmlns="urn:jboss:domain:keycloak:1.1"\/>/' /wildfly/standalone/configuration/standalone.xml && \
    sed -i -e 's/<security-domains>/&\n                <security-domain name="keycloak">\n                    <authentication>\n                        <login-module code="org.keycloak.adapters.jboss.KeycloakLoginModule" flag="required"\/>\n                    <\/authentication>\n                <\/security-domain>/' /wildfly/standalone/configuration/standalone.xml

# offline batch execution
ADD keycloak-entrypoint.sh /wildfly
#RUN /tmp/keycloak.sh
#RUN if [ -n "$WAR_NAME" ] && [ -n "$SECURE_DEPLOYMENT_ATTRS" ]; then /wildfly/bin/jboss-cli.sh --commands=embed-server,/subsystem=keycloak/secure-deployment=$WAR_NAME.war:add\($SECURE_DEPLOYMENT_ATTRS\),stop-embedded-server; fi

ENTRYPOINT [ "/wildfly/keycloak-entrypoint.sh" ]