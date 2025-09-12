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

import static com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer.CLIENT_ID3;
import static com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer.CLIENT_ID4;
import static com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer.CLIENT_ID5;
import static com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer.CLIENT_SECRET3;
import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;
import static com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS;
import static com.nimbusds.oauth2.sdk.GrantType.DEVICE_CODE;
import static com.nimbusds.oauth2.sdk.GrantType.PASSWORD;
import static com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_JWT;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT;
import static com.nimbusds.oauth2.sdk.token.TokenTypeURI.ACCESS_TOKEN;
import static com.nimbusds.oauth2.sdk.token.TokenTypeURI.REFRESH_TOKEN;
import static org.assertj.core.api.Assumptions.assumeThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakExtension;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserBehavior;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import org.apache.http.ssl.SSLContextBuilder;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Enum;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Values;

@ExtendWith(KeycloakExtension.class)
@ExtendWith(SoftAssertionsExtension.class)
public class OAuth2AgentKeycloakIT {

  private static boolean bouncyCastleAvailable;

  @InjectSoftAssertions private SoftAssertions soft;

  @BeforeAll
  static void probeForBouncyCastle() {
    try {
      Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
      bouncyCastleAvailable = true;
    } catch (ClassNotFoundException ignored) {
    }
  }

  @CartesianTest
  void clientSecretBasic(
      @Enum HttpClientType httpClientType,
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType initialGrantType,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .httpClientType(httpClientType)
                .grantType(initialGrantType)
                .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      boolean expectRefreshToken = initialGrantType != CLIENT_CREDENTIALS;
      assertAgent(agent, CLIENT_ID1, expectRefreshToken);
    }
  }

  @CartesianTest
  void clientSecretPost(
      @Enum HttpClientType httpClientType,
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType initialGrantType,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .httpClientType(httpClientType)
                .grantType(initialGrantType)
                .clientAuthenticationMethod(CLIENT_SECRET_POST)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, initialGrantType != CLIENT_CREDENTIALS);
    }
  }

  @CartesianTest
  void publicClient(
      @Enum HttpClientType httpClientType,
      @EnumLike(
              excludes = {"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"})
          GrantType initialGrantType,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .httpClientType(httpClientType)
                .grantType(initialGrantType)
                .clientAuthenticationMethod(NONE)
                .discoveryEnabled(false) // also test discovery disabled
                .clientId(new ClientID(CLIENT_ID2))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID2, true);
    }
  }

  @CartesianTest
  void clientSecretJwt(
      @Enum HttpClientType httpClientType,
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType initialGrantType,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .httpClientType(httpClientType)
                .grantType(initialGrantType)
                .clientId(new ClientID(CLIENT_ID3))
                .clientSecret(new Secret(CLIENT_SECRET3))
                .clientAuthenticationMethod(CLIENT_SECRET_JWT)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID3, initialGrantType != CLIENT_CREDENTIALS);
    }
  }

  @CartesianTest
  void privateKeyJwt(
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType initialGrantType,
      @Values(
              strings = {
                "/openssl/rsa_private_key_pkcs8.pem",
                "/openssl/rsa_private_key_pkcs1.pem",
                "/openssl/ecdsa_private_key.pem"
              })
          String resource,
      Builder envBuilder,
      @TempDir Path tempDir)
      throws Exception {
    assumeThat(bouncyCastleAvailable || resource.contains("pkcs8"))
        .as("BouncyCastle is required for RSA PKCS#1 and ECDSA keys")
        .isTrue();
    Path privateKeyPath = copyPrivateKey(resource, tempDir);
    JWSAlgorithm algorithm = resource.contains("rsa") ? JWSAlgorithm.RS256 : JWSAlgorithm.ES256;
    String clientId = resource.contains("rsa") ? CLIENT_ID4 : CLIENT_ID5;
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientId(new ClientID(clientId))
                .clientAuthenticationMethod(PRIVATE_KEY_JWT)
                .jwsAlgorithm(algorithm)
                .privateKey(privateKeyPath)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, clientId, initialGrantType != CLIENT_CREDENTIALS);
    }
  }

  @CartesianTest
  void pkce(
      @Values(booleans = {true, false}) boolean enabled,
      @EnumLike CodeChallengeMethod method,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(AUTHORIZATION_CODE)
                .pkceEnabled(enabled)
                .codeChallengeMethod(method)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, true);
    }
  }

  @CartesianTest
  void httpsCallback(
      @EnumLike CodeChallengeMethod method, Builder envBuilder, @TempDir Path tempDir)
      throws Exception {
    Path keyStorePath = tempDir.resolve("keystore.p12");
    try (InputStream is = getClass().getResourceAsStream("/openssl/mockserver.p12")) {
      Files.copy(Objects.requireNonNull(is), keyStorePath);
    }
    try (TestEnvironment env =
            envBuilder
                .grantType(AUTHORIZATION_CODE)
                .codeChallengeMethod(method)
                .callbackHttps(true)
                .sslKeyStorePath(keyStorePath)
                .sslKeyStorePassword("s3cr3t")
                .sslKeyStoreAlias("1")
                .userSslContext(
                    SSLContextBuilder.create()
                        .loadTrustMaterial(keyStorePath.toFile(), "s3cr3t".toCharArray())
                        .build())
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, true);
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent. No refresh
   * tokens are present.
   */
  @CartesianTest
  void impersonation1(
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType subjectGrantType,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(ACCESS_TOKEN) // request only access token
                .subjectGrantType(subjectGrantType)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, false);
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent. Refresh
   * tokens are present, which is why the client credentials grant cannot be used for the subject
   * token.
   */
  @CartesianTest
  void impersonation2(
      @EnumLike(
              excludes = {"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"})
          GrantType subjectGrantType,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(REFRESH_TOKEN) // request access and refresh tokens
                .subjectGrantType(subjectGrantType)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, subjectGrantType != CLIENT_CREDENTIALS);
    }
  }

  /**
   * Tests a simple delegation scenario with a fixed subject token obtained off-band, and the agent
   * using itws own access token as the actor token.
   */
  @Test
  void delegation1(Builder envBuilder) throws Exception {
    AccessToken subjectToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent subjectAgent = env.newAgent()) {
      subjectToken = subjectAgent.authenticate();
    }
    try (TestEnvironment env =
            envBuilder.grantType(TOKEN_EXCHANGE).subjectToken(subjectToken).build();
        OAuth2Agent agent = env.newAgent()) {
      AccessToken accessToken = agent.authenticate();
      introspectToken(accessToken, CLIENT_ID1);
    }
  }

  /**
   * Tests a simple delegation scenario with a fixed actor token, obtained off-band, and the agent
   * using its own access token as the subject token.
   */
  @Test
  void delegation2(Builder envBuilder) throws Exception {
    AccessToken actorToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent actorAgent = env.newAgent()) {
      actorToken = actorAgent.authenticate();
    }
    try (TestEnvironment env = envBuilder.grantType(TOKEN_EXCHANGE).actorToken(actorToken).build();
        OAuth2Agent agent = env.newAgent()) {
      AccessToken accessToken = agent.authenticate();
      introspectToken(accessToken, CLIENT_ID1);
    }
  }

  /**
   * Tests a delegation scenario where both the subject and actor tokens are dynamically obtained.
   * The subject token is obtained using a variable code grant, and the actor token using the client
   * credentials grant. Refresh tokens are requested, except for the client credentials grant where
   * they are not supported.
   */
  @CartesianTest
  void delegation3(
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType subjectGrantType,
      Builder envBuilder)
      throws Exception {
    boolean expectRefreshToken = subjectGrantType != CLIENT_CREDENTIALS;
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(expectRefreshToken ? REFRESH_TOKEN : ACCESS_TOKEN)
                .subjectGrantType(subjectGrantType)
                .actorGrantType(CLIENT_CREDENTIALS)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, expectRefreshToken);
    }
  }

  /**
   * Tests a delegation scenario where both the subject and actor tokens are dynamically obtained,
   * with the subject token agent using private key JWT authentication.
   *
   * <p>This test also tests the copying of agents, including subject and actor token agents.
   * Refresh tokens are requested except for the client credentials grant where they are not
   * supported.
   */
  @CartesianTest
  void delegation4(
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType subjectGrantType,
      Builder envBuilder,
      @TempDir Path tempDir)
      throws Exception {
    Path privateKeyPath = copyPrivateKey("/openssl/rsa_private_key_pkcs8.pem", tempDir);
    boolean expectRefreshToken = subjectGrantType != CLIENT_CREDENTIALS;
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .clientId(new ClientID(CLIENT_ID4))
                .clientAuthenticationMethod(PRIVATE_KEY_JWT)
                .jwsAlgorithm(JWSAlgorithm.RS256)
                .privateKey(privateKeyPath)
                .requestedTokenType(expectRefreshToken ? REFRESH_TOKEN : ACCESS_TOKEN)
                .subjectGrantType(subjectGrantType) // triggers a user emulator if necessary
                .subjectTokenConfig(
                    Map.of(
                        BasicConfig.GRANT_TYPE,
                        subjectGrantType.getValue(),
                        BasicConfig.SCOPE,
                        KeycloakContainer.SCOPE1,
                        BasicConfig.CLIENT_ID,
                        CLIENT_ID4,
                        BasicConfig.CLIENT_AUTH,
                        PRIVATE_KEY_JWT.getValue(),
                        ClientAssertionConfig.GROUP_NAME + "." + ClientAssertionConfig.PRIVATE_KEY,
                        privateKeyPath.toString(),
                        ClientAssertionConfig.GROUP_NAME + "." + ClientAssertionConfig.ALGORITHM,
                        JWSAlgorithm.RS256.getName()))
                .actorTokenConfig(
                    Map.of(
                        BasicConfig.GRANT_TYPE,
                        CLIENT_CREDENTIALS.getValue(),
                        BasicConfig.SCOPE,
                        KeycloakContainer.SCOPE1,
                        BasicConfig.CLIENT_ID,
                        CLIENT_ID1,
                        BasicConfig.CLIENT_SECRET,
                        KeycloakContainer.CLIENT_SECRET1,
                        BasicConfig.CLIENT_AUTH,
                        CLIENT_SECRET_BASIC.getValue()))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID4, expectRefreshToken);
      // test copy before and after close
      try (OAuth2Agent agent2 = agent.copy()) {
        assertAgent(agent2, CLIENT_ID4, expectRefreshToken);
      }
      agent.close();
      try (OAuth2Agent agent3 = agent.copy()) {
        assertAgent(agent3, CLIENT_ID4, expectRefreshToken);
      }
    }
  }

  /** Tests dynamically-obtained tokens with refresh forcibly disabled. */
  @Test
  void refreshDisabled(Builder envBuilder) throws Exception {
    try (TestEnvironment env = envBuilder.grantType(PASSWORD).tokenRefreshEnabled(false).build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      TokensResult firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getTokens().getAccessToken(), CLIENT_ID1);
      soft.assertThat(agent).extracting("tokenRefreshFuture").isNull();
    }
  }

  @Test
  void unauthorizedBadClientSecret(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.clientSecret(new Secret("BAD SECRET")).build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(type(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .extracting(ErrorObject::getHTTPStatusCode, ErrorObject::getCode)
          .containsExactly(401, "unauthorized_client");
    }
  }

  @Test
  void unauthorizedBadPassword(Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder.grantType(PASSWORD).password(new Secret("BAD PASSWORD")).build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(type(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .extracting(ErrorObject::getHTTPStatusCode, ErrorObject::getCode)
          .containsExactly(401, "invalid_grant");
    }
  }

  @Test
  void unauthorizedBadCode(Builder envBuilder) {
    try (TestEnvironment env =
        envBuilder
            .grantType(AUTHORIZATION_CODE)
            .userBehavior(
                UserBehavior.builder()
                    .from(UserBehavior.INTEGRATION_TESTS)
                    .emulateFailure(true)
                    .build())
            .build()) {
      try (OAuth2Agent agent = env.newAgent()) {
        soft.assertThatThrownBy(agent::authenticate)
            .asInstanceOf(type(OAuth2Exception.class))
            .extracting(OAuth2Exception::getErrorObject)
            .extracting(ErrorObject::getHTTPStatusCode, ErrorObject::getCode)
            .containsExactly(400, "invalid_grant"); // Keycloak replies with 400 instead of 401
      }
    }
  }

  @Test
  void deviceCodeAccessDenied(Builder envBuilder) {
    try (TestEnvironment env =
        envBuilder
            .grantType(DEVICE_CODE)
            .userBehavior(
                UserBehavior.builder()
                    .from(UserBehavior.INTEGRATION_TESTS)
                    .emulateFailure(true)
                    .build())
            .build()) {
      try (OAuth2Agent agent = env.newAgent()) {
        soft.assertThatThrownBy(agent::authenticate)
            .asInstanceOf(type(OAuth2Exception.class))
            .extracting(OAuth2Exception::getErrorObject)
            .extracting(ErrorObject::getHTTPStatusCode, ErrorObject::getCode)
            .containsExactly(400, "access_denied"); // Keycloak replies with 400 instead of 401
      }
    }
  }

  @Test
  void agentCopy(Builder envBuilder) throws Exception {
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent agent = env.newAgent()) {
      try (OAuth2Agent agent2 = agent.copy()) {
        assertAgent(agent2, CLIENT_ID1, false);
      }
      agent.close();
      try (OAuth2Agent agent3 = agent.copy()) {
        assertAgent(agent3, CLIENT_ID1, false);
      }
    }
  }

  private void assertAgent(OAuth2Agent agent, String clientId, boolean expectRefreshToken)
      throws Exception {
    // initial grant
    TokensResult initial = agent.authenticateInternal();
    introspectToken(initial.getTokens().getAccessToken(), clientId);
    // token refresh
    if (expectRefreshToken) {
      soft.assertThat(initial.getTokens().getRefreshToken()).isNotNull();
      TokensResult refreshed = agent.refreshCurrentTokens(initial).toCompletableFuture().get();
      introspectToken(refreshed.getTokens().getAccessToken(), clientId);
      soft.assertThat(refreshed.getTokens().getRefreshToken()).isNotNull();
    } else {
      soft.assertThat(initial.getTokens().getRefreshToken()).isNull();
    }
    // fetch new tokens
    TokensResult renewed = agent.fetchNewTokens().toCompletableFuture().get();
    introspectToken(renewed.getTokens().getAccessToken(), clientId);
    if (expectRefreshToken) {
      soft.assertThat(renewed.getTokens().getRefreshToken()).isNotNull();
    } else {
      soft.assertThat(renewed.getTokens().getRefreshToken()).isNull();
    }
  }

  private void introspectToken(AccessToken accessToken, String clientId) throws ParseException {
    soft.assertThat(accessToken).isNotNull();
    JWT jwt = JWTParser.parse(accessToken.getValue());
    soft.assertThat(jwt).isNotNull();
    soft.assertThat(jwt.getJWTClaimsSet().getStringClaim("azp")).isEqualTo(clientId);
    soft.assertThat(jwt.getJWTClaimsSet().getStringClaim("scope"))
        .contains(KeycloakContainer.SCOPE1);
  }

  private Path copyPrivateKey(String resource, Path tempDir) throws IOException {
    try (InputStream src = Objects.requireNonNull(getClass().getResource(resource)).openStream()) {
      Path dest = tempDir.resolve("private-key.pem");
      Files.copy(src, dest);
      return dest;
    }
  }
}
