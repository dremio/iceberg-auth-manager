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
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.CLIENT_CREDENTIALS;
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.DEVICE_CODE;
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.TOKEN_EXCHANGE;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent.MustFetchNewTokensException;
import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakAuthCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakDeviceCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserEmulator;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProviders;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

@ExtendWith(KeycloakTestEnvironment.class)
@ExtendWith(SoftAssertionsExtension.class)
public class OAuth2AgentKeycloakIT {

  @InjectSoftAssertions private SoftAssertions soft;

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void privateClientDiscoveryOn(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env = envBuilder.grantType(initialGrantType).build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.doAuthenticate();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      if (initialGrantType == GrantType.CLIENT_CREDENTIALS) {
        soft.assertThat(firstTokens.getRefreshToken()).isNull();
      } else {
        soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
        // token refresh
        Tokens refreshedTokens = agent.refreshCurrentTokens(firstTokens);
        introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
        soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void publicClientDiscoveryOff(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .grantType(initialGrantType)
                .privateClient(false)
                .discoveryEnabled(false)
                .clientId(TestConstants.CLIENT_ID2)
                .clientSecret(TestConstants.CLIENT_SECRET2)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.doAuthenticate();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID2);
      soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
      // token refresh
      Tokens refreshedTokens = agent.refreshCurrentTokens(firstTokens);
      introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID2);
      soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
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
      Tokens firstTokens = agent.doAuthenticate();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(firstTokens.getRefreshToken()).isNotNull();
      // token refresh
      Tokens refreshedTokens = agent.refreshCurrentTokens(firstTokens);
      introspectToken(refreshedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
    }
  }

  /**
   * Tests a simple impersonation scenario with the agent using its own token as the subject token,
   * and no actor token. The agent swaps its token for another one, roughly equivalent.
   */
  @ParameterizedTest
  @EnumSource(
      value = GrantType.class,
      names = {"CLIENT_CREDENTIALS", "PASSWORD", "AUTHORIZATION_CODE", "DEVICE_CODE"})
  void impersonation(GrantType initialGrantType, Builder envBuilder) {
    try (TestEnvironment env =
        envBuilder.grantType(initialGrantType).impersonationEnabled(true).build()) {
      try (OAuth2Agent agent = env.newAgent()) {
        // initial grant + impersonation
        Tokens impersonatedTokens = agent.doAuthenticate();
        introspectToken(impersonatedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
        // token refresh
        if (initialGrantType == GrantType.CLIENT_CREDENTIALS) {
          soft.assertThat(impersonatedTokens.getRefreshToken()).isNull();
        } else {
          soft.assertThat(impersonatedTokens.getRefreshToken()).isNotNull();
          Tokens refreshedTokens = agent.refreshCurrentTokens(impersonatedTokens);
          soft.assertThat(refreshedTokens.getRefreshToken()).isNotNull();
          // re-impersonation after refresh
          impersonatedTokens = agent.maybeImpersonate(refreshedTokens);
          introspectToken(impersonatedTokens.getAccessToken(), TestConstants.CLIENT_ID1);
          soft.assertThat(impersonatedTokens.getRefreshToken()).isNotNull();
          // should keep the same refresh token
          soft.assertThat(impersonatedTokens.getRefreshToken())
              .isEqualTo(refreshedTokens.getRefreshToken());
        }
      }
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
        envBuilder
            .grantType(CLIENT_CREDENTIALS)
            .impersonationEnabled(true)
            .tokenExchangeConfig(
                TokenExchangeConfig.builder()
                    .subjectToken(TypedToken.of(subjectToken))
                    .actorTokenProvider(TokenProviders.CURRENT_ACCESS_TOKEN)
                    .build())
            .build()) {
      try (OAuth2Agent agent = env.newAgent()) {
        AccessToken accessToken = agent.authenticate();
        introspectToken(accessToken, TestConstants.CLIENT_ID1);
      }
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
        envBuilder
            .grantType(CLIENT_CREDENTIALS)
            .impersonationEnabled(true)
            .tokenExchangeConfig(
                TokenExchangeConfig.builder()
                    .subjectTokenProvider(TokenProviders.CURRENT_ACCESS_TOKEN)
                    .actorToken(TypedToken.of(actorToken))
                    .build())
            .build()) {
      try (OAuth2Agent agent = env.newAgent()) {
        AccessToken accessToken = agent.authenticate();
        introspectToken(accessToken, TestConstants.CLIENT_ID1);
      }
    }
  }

  /** Tests dynamically-obtained tokens with refresh forcibly disabled. */
  @Test
  void refreshDisabled(Builder envBuilder) {
    try (TestEnvironment env = envBuilder.grantType(PASSWORD).tokenRefreshEnabled(false).build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.doAuthenticate();
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
      Tokens firstTokens = agent.doAuthenticate();
      soft.assertThat(firstTokens.getAccessToken().getPayload())
          .isEqualTo(accessToken.getPayload());
      soft.assertThat(agent).extracting("tokenRefreshFuture").isNull();
      // cannot refresh the token
      soft.assertThatThrownBy(() -> agent.refreshCurrentTokens(firstTokens))
          .isInstanceOf(MustFetchNewTokensException.class);
      // cannot fetch new tokens
      soft.assertThatThrownBy(agent::fetchNewTokens)
          .isInstanceOf(OAuth2Exception.class)
          .hasMessageContaining("Invalid client or Invalid client credentials");
    }
  }

  /**
   * Tests token exchange as initial grant type. Can only work with a fixed subject token, as the
   * agent does not have a token to exchange initially.
   */
  @Test
  void initialTokenExchange(Builder envBuilder) {
    AccessToken accessToken;
    try (TestEnvironment env = envBuilder.build();
        OAuth2Agent agent = env.newAgent()) {
      accessToken = agent.authenticate();
    }
    try (TestEnvironment env =
            envBuilder
                .grantType(TOKEN_EXCHANGE)
                .tokenExchangeConfig(
                    TokenExchangeConfig.builder().subjectToken(TypedToken.of(accessToken)).build())
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      Tokens firstTokens = agent.doAuthenticate();
      introspectToken(firstTokens.getAccessToken(), TestConstants.CLIENT_ID1);
      // keycloak does not send refresh tokens
      soft.assertThat(firstTokens.getRefreshToken()).isNull();
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
