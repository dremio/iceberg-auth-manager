/*
 * Copyright (C) 2025 Dremio Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.test.junit;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.TLS_CLIENT_AUTH;

import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestCertificates;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironmentExtension;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.google.common.base.Preconditions;
import java.time.Duration;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;

/**
 * JUnit 5 extension that boots a Keycloak container configured for RFC 8705 mutual-TLS integration
 * tests:
 *
 * <ul>
 *   <li>HTTPS termination via the dasniko-bundled server cert, with {@code HttpsClientAuth.REQUEST}
 *       so a client cert is asked for but not required at the TLS layer (the actual identity check
 *       is the X.509 client authenticator on the Keycloak client).
 *   <li>The {@link TestCertificates} RSA certificate is added to Keycloak's truststore so the TLS
 *       handshake completes when the agent presents it.
 *   <li>Four mTLS clients are registered, covering the cartesian product of {@code tls_client_auth}
 *       / {@code self_signed_tls_client_auth} and cert-bound / non-cert-bound access tokens.
 * </ul>
 *
 * Tests using this extension must trust Keycloak's self-signed server cert; the simplest way is to
 * set {@code ssl.trust-all=true} in {@code HttpConfig} for the test agent.
 */
public class MtlsKeycloakExtension extends TestEnvironmentExtension
    implements BeforeAllCallback, AfterAllCallback {

  public static final String CLIENT_ID_TLS_PKI = "ClientMtlsPki";
  public static final String CLIENT_ID_TLS_PKI_BOUND = "ClientMtlsPkiBound";
  public static final String CLIENT_ID_TLS_SELF_SIGNED = "ClientMtlsSelfSigned";
  public static final String CLIENT_ID_TLS_SELF_SIGNED_BOUND = "ClientMtlsSelfSignedBound";

  public static final String SCOPE1 = TestConstants.SCOPE1.toString();

  public static final Duration ACCESS_TOKEN_LIFESPAN = Duration.ofSeconds(15);
  public static final Duration REFRESH_TOKEN_LIFESPAN = Duration.ofSeconds(20);

  @Override
  public void beforeAll(ExtensionContext context) {
    TestCertificates certs = TestCertificates.instance();
    String certBase64 = certs.getRsaCertificateBase64();
    KeycloakContainer keycloak =
        new KeycloakContainer()
            .withMutualTls(certs.getRsaCertificatePem())
            .withScope(SCOPE1)
            .withAccessTokenLifespan(ACCESS_TOKEN_LIFESPAN)
            .withRefreshTokenLifespan(REFRESH_TOKEN_LIFESPAN)
            .withMtlsClient(CLIENT_ID_TLS_PKI, TLS_CLIENT_AUTH.getValue(), certBase64, false)
            .withMtlsClient(CLIENT_ID_TLS_PKI_BOUND, TLS_CLIENT_AUTH.getValue(), certBase64, true)
            .withMtlsClient(
                CLIENT_ID_TLS_SELF_SIGNED,
                SELF_SIGNED_TLS_CLIENT_AUTH.getValue(),
                certBase64,
                false)
            .withMtlsClient(
                CLIENT_ID_TLS_SELF_SIGNED_BOUND,
                SELF_SIGNED_TLS_CLIENT_AUTH.getValue(),
                certBase64,
                true);
    keycloak.start();
    context
        .getStore(ExtensionContext.Namespace.GLOBAL)
        .put(KeycloakContainer.class.getName(), keycloak);
  }

  @Override
  public boolean supportsParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return parameterContext.getParameter().getType().equals(KeycloakContainer.class)
        || super.supportsParameter(parameterContext, extensionContext);
  }

  @Override
  public Object resolveParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    if (parameterContext.getParameter().getType().equals(KeycloakContainer.class)) {
      return extensionContext
          .getStore(ExtensionContext.Namespace.GLOBAL)
          .get(KeycloakContainer.class.getName(), KeycloakContainer.class);
    }
    return super.resolveParameter(parameterContext, extensionContext);
  }

  @Override
  public void afterAll(ExtensionContext context) {
    KeycloakContainer keycloak =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .remove(KeycloakContainer.class.getName(), KeycloakContainer.class);
    if (keycloak != null) {
      keycloak.close();
    }
  }

  @Override
  protected ImmutableTestEnvironment.Builder newTestEnvironmentBuilder(ExtensionContext context) {
    KeycloakContainer keycloak =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .get(KeycloakContainer.class.getName(), KeycloakContainer.class);
    Preconditions.checkNotNull(keycloak, "Keycloak container not found in extension context");
    return TestEnvironment.builder()
        .unitTest(false)
        .serverRootUrl(keycloak.getRootUrl())
        .authorizationServerUrl(keycloak.getIssuerUrl())
        .tokenEndpoint(keycloak.getTokenEndpoint())
        .authorizationEndpoint(keycloak.getAuthEndpoint())
        .deviceAuthorizationEndpoint(keycloak.getDeviceAuthEndpoint())
        // Disable subject/actor tokens to keep the env builder usable for client-credentials only.
        .subjectToken(null)
        .actorToken(null)
        .subjectClientId(TestConstants.CLIENT_ID1)
        .subjectClientSecret(TestConstants.CLIENT_SECRET1)
        .subjectScope(TestConstants.SCOPE1)
        .actorClientId(TestConstants.CLIENT_ID1)
        .actorClientSecret(TestConstants.CLIENT_SECRET1)
        .actorScope(TestConstants.SCOPE1)
        .audience(null)
        .resource(null);
  }
}
