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

import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;
import static com.nimbusds.oauth2.sdk.GrantType.DEVICE_CODE;
import static com.nimbusds.oauth2.sdk.GrantType.PASSWORD;
import static com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestPemUtils;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakExtension;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserBehavior;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(KeycloakExtension.class)
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
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
      })
  void clientSecretBasic(GrantType initialGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      boolean expectRefreshToken = initialGrantType != GrantType.CLIENT_CREDENTIALS;
      assertAgent(agent, TestConstants.CLIENT_ID1, expectRefreshToken);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
      })
  void clientSecretPost(GrantType initialGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(
          agent, TestConstants.CLIENT_ID1, initialGrantType != GrantType.CLIENT_CREDENTIALS);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
      })
  void publicClient(GrantType initialGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .discoveryEnabled(false) // also test discovery disabled
                .clientId(TestConstants.CLIENT_ID2)
                .clientSecret(TestConstants.CLIENT_SECRET2)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, TestConstants.CLIENT_ID2, true);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
      })
  void clientSecretJwt(GrantType initialGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientId(TestConstants.CLIENT_ID3)
                .clientSecret(TestConstants.CLIENT_SECRET3)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(
          agent, TestConstants.CLIENT_ID3, initialGrantType != GrantType.CLIENT_CREDENTIALS);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
      })
  void privateKeyJwt(GrantType initialGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .clientId(TestConstants.CLIENT_ID4)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertionConfig(
                    ClientAssertionConfig.builder()
                        .algorithm(JWSAlgorithm.RS256)
                        .privateKey(privateKeyPath)
                        .build())
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(
          agent, TestConstants.CLIENT_ID4, initialGrantType != GrantType.CLIENT_CREDENTIALS);
    }
  }

  @ParameterizedTest
  @CsvSource({"false, S256", "true, S256", "true, plain"})
  void pkce(boolean enabled, CodeChallengeMethod method, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(AUTHORIZATION_CODE)
                .pkceEnabled(enabled)
                .codeChallengeMethod(method)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, TestConstants.CLIENT_ID1, true);
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent. No refresh
   * tokens are present.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code"
      })
  void impersonation1(GrantType subjectGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(TokenTypeURI.ACCESS_TOKEN) // request only access token
                .subjectGrantType(subjectGrantType)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, TestConstants.CLIENT_ID1, false);
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent. Refresh
   * tokens are present, which is why the client credentials grant cannot be used for the subject
   * token.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {"password", "authorization_code", "urn:ietf:params:oauth:grant-type:device_code"})
  void impersonation2(GrantType subjectGrantType, Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(TokenTypeURI.REFRESH_TOKEN) // request access and refresh tokens
                .subjectGrantType(subjectGrantType)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(
          agent, TestConstants.CLIENT_ID1, subjectGrantType != GrantType.CLIENT_CREDENTIALS);
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
      introspectToken(accessToken, TestConstants.CLIENT_ID1);
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
      introspectToken(accessToken, TestConstants.CLIENT_ID1);
    }
  }

  /**
   * Tests a delegation scenario where both the subject and actor tokens are dynamically obtained.
   * The subject token is obtained using a variable code grant, and the actor token using the client
   * credentials grant. Refresh tokens are requested, except for the client credentials grant where
   * they are not supported.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code"
      })
  void delegation3(GrantType subjectGrantType, Builder envBuilder) throws Exception {
    boolean expectRefreshToken = subjectGrantType != GrantType.CLIENT_CREDENTIALS;
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .requestedTokenType(
                    expectRefreshToken ? TokenTypeURI.REFRESH_TOKEN : TokenTypeURI.ACCESS_TOKEN)
                .subjectGrantType(subjectGrantType)
                .actorGrantType(GrantType.CLIENT_CREDENTIALS)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, TestConstants.CLIENT_ID1, expectRefreshToken);
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
  @ParameterizedTest
  @ValueSource(
      strings = {
        "client_credentials",
        "password",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code"
      })
  void delegation4(GrantType subjectGrantType, Builder envBuilder) throws Exception {
    boolean expectRefreshToken = subjectGrantType != GrantType.CLIENT_CREDENTIALS;
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .clientId(TestConstants.CLIENT_ID4)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertionConfig(
                    ClientAssertionConfig.builder()
                        .algorithm(JWSAlgorithm.RS256)
                        .privateKey(privateKeyPath)
                        .build())
                .requestedTokenType(
                    expectRefreshToken ? TokenTypeURI.REFRESH_TOKEN : TokenTypeURI.ACCESS_TOKEN)
                .subjectGrantType(subjectGrantType) // triggers a user emulator if necessary
                .subjectTokenConfig(
                    Map.of(
                        Basic.GRANT_TYPE,
                        subjectGrantType.getValue(),
                        Basic.SCOPE,
                        TestConstants.SCOPE1.toString(),
                        Basic.CLIENT_ID,
                        TestConstants.CLIENT_ID4.getValue(),
                        Basic.CLIENT_AUTH,
                        ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                        OAuth2Properties.ClientAssertion.PRIVATE_KEY,
                        privateKeyPath.toString(),
                        OAuth2Properties.ClientAssertion.ALGORITHM,
                        JWSAlgorithm.RS256.getName()))
                .actorTokenConfig(
                    Map.of(
                        Basic.GRANT_TYPE,
                        GrantType.CLIENT_CREDENTIALS.getValue(),
                        Basic.SCOPE,
                        TestConstants.SCOPE1.toString(),
                        Basic.CLIENT_ID,
                        TestConstants.CLIENT_ID1.getValue(),
                        Basic.CLIENT_SECRET,
                        TestConstants.CLIENT_SECRET1.getValue(),
                        Basic.CLIENT_AUTH,
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, TestConstants.CLIENT_ID4, expectRefreshToken);
      // test copy before and after close
      try (OAuth2Agent agent2 = agent.copy()) {
        assertAgent(agent2, TestConstants.CLIENT_ID4, expectRefreshToken);
      }
      agent.close();
      try (OAuth2Agent agent3 = agent.copy()) {
        assertAgent(agent3, TestConstants.CLIENT_ID4, expectRefreshToken);
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
      introspectToken(firstTokens.getTokens().getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(agent).extracting("tokenRefreshFuture").isNull();
    }
  }

  /**
   * Tests a fixed initial token with standard OAuth2 dialect. It's not possible to refresh or renew
   * the token since there is no client id and secret available, so token refresh is disabled.
   */
  @Test
  void staticToken(Builder envBuilder) {
    AccessToken accessToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent agent = env.newAgent()) {
      accessToken = agent.authenticate();
    }
    try (TestEnvironment env = envBuilder.token(accessToken).tokenRefreshEnabled(false).build();
        OAuth2Agent agent = env.newAgent()) {
      // should use the fixed token
      TokensResult firstTokens = agent.authenticateInternal();
      soft.assertThat(firstTokens.getTokens().getAccessToken().getValue())
          .isEqualTo(accessToken.getValue());
      soft.assertThat(agent).extracting("tokenRefreshFuture").isNull();
      // cannot refresh the token
      soft.assertThat(agent.refreshCurrentTokens(firstTokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Agent.MustFetchNewTokensException.class);
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
        assertAgent(agent2, TestConstants.CLIENT_ID1, false);
      }
      agent.close();
      try (OAuth2Agent agent3 = agent.copy()) {
        assertAgent(agent3, TestConstants.CLIENT_ID1, false);
      }
    }
  }

  private void assertAgent(OAuth2Agent agent, ClientID clientId, boolean expectRefreshToken)
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

  private void introspectToken(AccessToken accessToken, ClientID clientId) throws ParseException {
    soft.assertThat(accessToken).isNotNull();
    JWT jwt = JWTParser.parse(accessToken.getValue());
    soft.assertThat(jwt).isNotNull();
    soft.assertThat(jwt.getJWTClaimsSet().getStringClaim("azp")).isEqualTo(clientId.getValue());
    soft.assertThat(jwt.getJWTClaimsSet().getStringClaim("scope"))
        .contains(TestConstants.SCOPE1.toString());
  }
}
