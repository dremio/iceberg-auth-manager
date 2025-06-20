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

import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.AUTHORIZATION_CODE;
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.DEVICE_CODE;
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.TOKEN_EXCHANGE;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthentication;
import com.dremio.iceberg.authmgr.oauth2.auth.JwtSigningAlgorithm;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestPemUtils;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakAuthCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakDeviceCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserEmulator;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

@ExtendWith(KeycloakTestEnvironment.class)
@ExtendWith(SoftAssertionsExtension.class)
public class OAuth2AgentKeycloakIT {

  private static Path privateKeyPath;

  @InjectSoftAssertions private SoftAssertions soft;

  @BeforeAll
  static void copyPrivateKeyFile(@TempDir Path tempDir) {
    privateKeyPath = Paths.get(tempDir.toString(), "key.pem");
    TestPemUtils.copyPrivateKey(privateKeyPath);
  }

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {
        "CLIENT_CREDENTIALS", "PASSWORD",
        "AUTHORIZATION_CODE", "DEVICE_CODE"
      })
  void clientSecretBasic(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientAuthentication(ClientAuthentication.CLIENT_SECRET_BASIC)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      if (initialGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(firstTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
        // token refresh
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(firstTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void clientSecretPost(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientAuthentication(ClientAuthentication.CLIENT_SECRET_POST)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      if (initialGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(firstTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
        // token refresh
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(firstTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void publicClient(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .privateClient(false)
                .discoveryEnabled(false) // also test discovery disabled
                .clientId(TestConstants.CLIENT_ID2)
                .clientSecret(TestConstants.CLIENT_SECRET2)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID2);
      soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
      // token refresh
      Tokens refreshedTokens = agent.refreshCurrentTokens(firstTokens).toCompletableFuture().join();
      introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID2);
      soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void clientSecretJwt(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientId(TestConstants.CLIENT_ID3)
                .clientSecret(TestConstants.CLIENT_SECRET3)
                .clientAuthentication(ClientAuthentication.CLIENT_SECRET_JWT)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID3);
      if (initialGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(firstTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
        // token refresh
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(firstTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID3);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void privateKeyJwt(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientId(TestConstants.CLIENT_ID4)
                .clientAuthentication(ClientAuthentication.PRIVATE_KEY_JWT)
                .clientAssertionConfig(
                    ClientAssertionConfig.builder()
                        .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                        .privateKey(privateKeyPath)
                        .build())
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID4);
      if (initialGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(firstTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
        // token refresh
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(firstTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID4);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
    }
  }

  @ParameterizedTest
  @CsvSource({"false, S256", "true, S256", "true, PLAIN"})
  void pkce(boolean enabled, PkceTransformation transformation, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(AUTHORIZATION_CODE)
                .pkceEnabled(enabled)
                .pkceTransformation(transformation)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.authenticateInternal();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
      // token refresh
      Tokens refreshedTokens = agent.refreshCurrentTokens(firstTokens).toCompletableFuture().join();
      introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent. No refresh
   * tokens are present.
   */
  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void impersonation1(GrantType subjectGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(TypedToken.URN_ACCESS_TOKEN) // request only access token
                .subjectGrantType(subjectGrantType)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant + impersonation
      Tokens impersonatedTokens = agent.authenticateInternal();
      introspectToken(impersonatedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      // token refresh
      soft.assertThat(impersonatedTokens.getRefreshToken()).isNull();
      // fetch new tokens
      Tokens renewedTokens = agent.fetchNewTokens().toCompletableFuture().join();
      introspectToken(renewedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(renewedTokens.getRefreshToken()).isNull();
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent. Refresh
   * tokens are present, except when the subject token's grant was client credentials: since no
   * refresh token is returned in this case for the subject token, the exchanged token does not have
   * a refresh token either.
   */
  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void impersonation2(GrantType subjectGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(
                    TypedToken.URN_REFRESH_TOKEN) // request access and refresh tokens
                .subjectGrantType(subjectGrantType)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant + impersonation
      Tokens impersonatedTokens = agent.authenticateInternal();
      introspectToken(impersonatedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      // token refresh
      if (subjectGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(impersonatedTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(impersonatedTokens.getRefreshToken()).isNotNull();
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(impersonatedTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
      // fetch new tokens
      Tokens renewedTokens = agent.fetchNewTokens().toCompletableFuture().join();
      introspectToken(renewedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
    }
  }

  /** Tests client assertions with subject impersonation. */
  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void impersonation3(GrantType subjectGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .clientId(TestConstants.CLIENT_ID4)
                .clientAuthentication(ClientAuthentication.PRIVATE_KEY_JWT)
                .clientAssertionConfig(
                    ClientAssertionConfig.builder()
                        .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                        .privateKey(privateKeyPath)
                        .build())
                .requestedTokenType(
                    TypedToken.URN_REFRESH_TOKEN) // request access and refresh tokens
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.GRANT_TYPE, subjectGrantType.name(),
                        OAuth2Properties.Basic.SCOPE, TestConstants.SCOPE1,
                        OAuth2Properties.Basic.CLIENT_ID, TestConstants.CLIENT_ID4,
                        OAuth2Properties.Basic.CLIENT_AUTH,
                            ClientAuthentication.PRIVATE_KEY_JWT.name(),
                        OAuth2Properties.ClientAssertion.PRIVATE_KEY, privateKeyPath.toString(),
                        OAuth2Properties.ClientAssertion.ALGORITHM,
                            JwtSigningAlgorithm.RSA_SHA256.name()))
                .actorTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.GRANT_TYPE, GrantType.CLIENT_CREDENTIALS.name(),
                        OAuth2Properties.Basic.SCOPE, TestConstants.SCOPE1,
                        OAuth2Properties.Basic.CLIENT_ID, TestConstants.CLIENT_ID1,
                        OAuth2Properties.Basic.CLIENT_SECRET, TestConstants.CLIENT_SECRET1,
                        OAuth2Properties.Basic.CLIENT_AUTH,
                            ClientAuthentication.CLIENT_SECRET_BASIC.name()))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant + impersonation
      Tokens impersonatedTokens = agent.authenticateInternal();
      introspectToken(impersonatedTokens.getAccessToken(), TestConstants.CLIENT_ID4);
      // token refresh
      if (subjectGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(impersonatedTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(impersonatedTokens.getRefreshToken()).isNotNull();
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(impersonatedTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID4);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
      // fetch new tokens
      Tokens renewedTokens = agent.fetchNewTokens().toCompletableFuture().join();
      introspectToken(renewedTokens.getAccessToken(), TestConstants.CLIENT_ID4);
    }
  }

  /**
   * Tests a simple delegation scenario with a fixed subject token obtained off-band, and the agent
   * using itws own access token as the actor token.
   */
  @Test
  void delegation1(Builder envBuilder) {
    AccessToken subjectToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent subjectAgent = env.newAgent()) {
      subjectToken = subjectAgent.authenticate();
    }
    try (TestEnvironment env =
            envBuilder.grantType(TOKEN_EXCHANGE).subjectToken(subjectToken.getPayload()).build();
        OAuth2Agent agent = env.newAgent()) {
      AccessToken accessToken = agent.authenticate();
      introspectToken(accessToken, TestConstants.CLIENT_ID1);
    }
  }

  /**
   * Tests a simple delegation scenario with a fixed actor token, obtained off-band, and the agent
   * using its own access token as the subject token.
   */
  @Test
  void delegation2(Builder envBuilder) {
    AccessToken actorToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent actorAgent = env.newAgent()) {
      actorToken = actorAgent.authenticate();
    }
    try (TestEnvironment env =
            envBuilder.grantType(TOKEN_EXCHANGE).actorToken(actorToken.getPayload()).build();
        OAuth2Agent agent = env.newAgent()) {
      AccessToken accessToken = agent.authenticate();
      introspectToken(accessToken, TestConstants.CLIENT_ID1);
    }
  }

  /**
   * Tests a delegation scenario where both the subject and actor tokens are dynamically obtained.
   * The subject token is obtained using the authorization code grant, and the actor token using the
   * client credentials grant. Refresh tokens are present.
   */
  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void delegation3(GrantType subjectGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(
                    TypedToken.URN_REFRESH_TOKEN) // request access and refresh tokens
                .subjectTokenConfig(
                    Map.of(OAuth2Properties.Basic.GRANT_TYPE, subjectGrantType.getCanonicalName()))
                .actorTokenConfig(
                    Map.of(OAuth2Properties.Basic.GRANT_TYPE, GrantType.CLIENT_CREDENTIALS.name()))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant + impersonation
      Tokens impersonatedTokens = agent.authenticateInternal();
      introspectToken(impersonatedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      // token refresh
      if (subjectGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(impersonatedTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(impersonatedTokens.getRefreshToken()).isNotNull();
        Tokens refreshedTokens =
            agent.refreshCurrentTokens(impersonatedTokens).toCompletableFuture().join();
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
      // fetch new tokens
      Tokens renewedTokens = agent.fetchNewTokens().toCompletableFuture().join();
      introspectToken(renewedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
    }
  }

  /** Tests dynamically-obtained tokens with refresh forcibly disabled. */
  @Test
  void refreshDisabled(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.grantType(PASSWORD).tokenRefreshEnabled(false).build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.getCurrentTokens();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(agent).extracting("tokenRefreshFuture").isNull();
    }
  }

  /**
   * Tests a fixed initial token with standard OAuth2 dialect. It's not possible to refresh or renew
   * the token since there is no client id and secret available, so token refresh is disabled.
   */
  @Test
  void fixedToken(Builder envBuilder) {
    AccessToken accessToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent agent = env.newAgent()) {
      accessToken = agent.authenticate();
    }
    try (TestEnvironment env =
            envBuilder.token(accessToken.getPayload()).tokenRefreshEnabled(false).build();
        OAuth2Agent agent = env.newAgent()) {
      // should use the fixed token
      Tokens firstTokens = agent.authenticateInternal();
      soft.assertThat(firstTokens.getAccessToken().getPayload())
          .isEqualTo(accessToken.getPayload());
      soft.assertThat(agent).extracting("tokenRefreshFuture").isNull();
      // cannot refresh the token
      soft.assertThat(agent.refreshCurrentTokens(firstTokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Agent.MustFetchNewTokensException.class);
      // cannot fetch new tokens
      soft.assertThat(agent.fetchNewTokens())
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Exception.class)
          .withMessageContaining("Invalid client or Invalid client credentials");
    }
  }

  @Test
  void unauthorizedBadClientSecret(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.clientSecret("BAD SECRET").build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(type(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorResponse)
          .extracting(ErrorResponse::code)
          .isEqualTo(401);
    }
  }

  @Test
  void unauthorizedBadPassword(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.grantType(PASSWORD).password("BAD PASSWORD").build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(type(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorResponse)
          .extracting(ErrorResponse::code)
          .isEqualTo(401);
    }
  }

  @Test
  void unauthorizedBadCode(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.grantType(AUTHORIZATION_CODE).build()) {
      UserEmulator user = env.getUser();
      ((KeycloakAuthCodeUserEmulator) user).overrideAuthorizationCode("BAD_CODE", 401);
      try (OAuth2Agent agent = env.newAgent()) {
        soft.assertThatThrownBy(agent::authenticate)
            .asInstanceOf(type(OAuth2Exception.class))
            .extracting(OAuth2Exception::getErrorResponse)
            .extracting(ErrorResponse::code)
            .isEqualTo(400); // Keycloak replies with 400 instead of 401
      }
    }
  }

  @Test
  void deviceCodeAccessDenied(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.grantType(DEVICE_CODE).build()) {
      UserEmulator user = env.getUser();
      ((KeycloakDeviceCodeUserEmulator) user).denyConsent();
      try (OAuth2Agent agent = env.newAgent()) {
        soft.assertThatThrownBy(agent::authenticate)
            .asInstanceOf(type(OAuth2Exception.class))
            .extracting(OAuth2Exception::getErrorResponse)
            .extracting(ErrorResponse::code, ErrorResponse::type)
            .containsExactly(400, "access_denied"); // Keycloak replies with 400 instead of 401
      }
    }
  }

  private void introspectToken(AccessToken accessToken, String clientId) {
    soft.assertThat(accessToken).isNotNull();
    DecodedJWT jwt = JWT.decode(accessToken.getPayload());
    soft.assertThat(jwt).isNotNull();
    soft.assertThat(jwt.getClaim("azp").asString()).isEqualTo(clientId);
    soft.assertThat(jwt.getClaim("scope").asString()).contains(TestConstants.SCOPE1);
  }
}
