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
package com.dremio.iceberg.authmgr.oauth2.agent;

import static com.dremio.iceberg.authmgr.oauth2.test.junit.MtlsKeycloakExtension.CLIENT_ID_TLS_PKI;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.MtlsKeycloakExtension.CLIENT_ID_TLS_PKI_BOUND;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.MtlsKeycloakExtension.CLIENT_ID_TLS_SELF_SIGNED;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.MtlsKeycloakExtension.CLIENT_ID_TLS_SELF_SIGNED_BOUND;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.MtlsKeycloakExtension.SCOPE1;
import static com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.TLS_CLIENT_AUTH;

import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestCertificates;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.junit.MtlsKeycloakExtension;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Values;

/**
 * End-to-end RFC 8705 tests against a real Keycloak with mutual-TLS enabled. The Keycloak container
 * terminates HTTPS with the dasniko-bundled server cert and trusts the {@link TestCertificates} RSA
 * cert as the client cert. Four clients are pre-registered (cartesian product of {@code
 * tls_client_auth} / {@code self_signed_tls_client_auth} × cert-bound / non-cert-bound); each test
 * selects one and walks the agent through initial grant + refresh + renew, asserting that the
 * issued access tokens have the expected {@code cnf.x5t#S256} confirmation claim when cert-bound.
 */
@ExtendWith(MtlsKeycloakExtension.class)
@ExtendWith(SoftAssertionsExtension.class)
public class OAuth2AgentMtlsKeycloakIT {

  @InjectSoftAssertions private SoftAssertions soft;

  @CartesianTest
  void mtlsClientAuth(
      @Values(
              strings = {
                CLIENT_ID_TLS_PKI,
                CLIENT_ID_TLS_PKI_BOUND,
                CLIENT_ID_TLS_SELF_SIGNED,
                CLIENT_ID_TLS_SELF_SIGNED_BOUND
              })
          String clientId,
      Builder envBuilder)
      throws Exception {
    ClientAuthenticationMethod method =
        clientId.contains("SelfSigned") ? SELF_SIGNED_TLS_CLIENT_AUTH : TLS_CLIENT_AUTH;
    boolean expectCertBound = clientId.endsWith("Bound");
    TestCertificates certs = TestCertificates.instance();
    try (TestEnvironment env =
            envBuilder
                .grantType(CLIENT_CREDENTIALS)
                .clientId(new ClientID(clientId))
                .clientAuthenticationMethod(method)
                .httpClientType(HttpClientType.APACHE)
                .sslKeyStorePath(certs.getRsaKeyStore())
                .sslKeyStorePassword(certs.getKeyStorePassword())
                .sslKeyStoreAlias("1")
                // Keycloak presents the dasniko-bundled self-signed server cert; trust it.
                .sslTrustAll(true)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      String expectedThumbprint = thumbprintBase64Url(certs);
      TokensResult initial = agent.authenticateInternal();
      verifyToken(initial, clientId, expectCertBound, expectedThumbprint);
      // Client-credentials grant in Keycloak does not return refresh tokens.
      soft.assertThat(initial.getTokens().getRefreshToken()).isNull();
      TokensResult renewed = agent.fetchNewTokens().toCompletableFuture().get();
      verifyToken(renewed, clientId, expectCertBound, expectedThumbprint);
    }
  }

  /**
   * Wrong key store presented to Keycloak: the request must be rejected. Uses the ECDSA keystore
   * which is not registered with any client. The failure can surface either at the TLS layer
   * (Keycloak's truststore doesn't include this cert) or at the X.509 authenticator (thumbprint
   * mismatch); both are valid "wrong cert" outcomes.
   */
  @Test
  void mtlsWrongClientCert(Builder envBuilder) {
    TestCertificates certs = TestCertificates.instance();
    try (TestEnvironment env =
            envBuilder
                .grantType(CLIENT_CREDENTIALS)
                .clientId(new ClientID(CLIENT_ID_TLS_SELF_SIGNED))
                .clientAuthenticationMethod(SELF_SIGNED_TLS_CLIENT_AUTH)
                .httpClientType(HttpClientType.APACHE)
                .sslKeyStorePath(certs.getEcdsaKeyStore())
                .sslKeyStorePassword(certs.getKeyStorePassword())
                .sslKeyStoreAlias("1")
                .sslTrustAll(true)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate).isInstanceOf(RuntimeException.class);
    }
  }

  private void verifyToken(
      TokensResult tokens, String clientId, boolean expectCertBound, String expectedThumbprint)
      throws ParseException {
    AccessToken accessToken = tokens.getTokens().getAccessToken();
    soft.assertThat(accessToken).isNotNull();
    JWT jwt = JWTParser.parse(accessToken.getValue());
    soft.assertThat(jwt.getJWTClaimsSet().getStringClaim("azp")).isEqualTo(clientId);
    soft.assertThat(jwt.getJWTClaimsSet().getStringClaim("scope")).contains(SCOPE1);
    Map<String, Object> cnf = jwt.getJWTClaimsSet().getJSONObjectClaim("cnf");
    if (expectCertBound) {
      soft.assertThat(cnf)
          .as("cnf claim must be present on cert-bound access token (RFC 8705 §3)")
          .isNotNull();
      if (cnf != null) {
        soft.assertThat(cnf.get("x5t#S256"))
            .as("cnf.x5t#S256 must match the client cert thumbprint")
            .isEqualTo(expectedThumbprint);
      }
    } else {
      // The non-bound clients should not produce a cnf claim.
      soft.assertThat(cnf).isNull();
    }
  }

  private static String thumbprintBase64Url(TestCertificates certs) throws Exception {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] hash = sha256.digest(certs.getRsaCertificate().getEncoded());
    return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
  }
}
