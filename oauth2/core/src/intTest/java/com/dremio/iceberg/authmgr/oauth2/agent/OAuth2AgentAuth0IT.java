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

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junitpioneer.jupiter.cartesian.CartesianTest;

/**
 * Integration tests for {@link OAuth2Agent} with Auth0.
 *
 * <p>These tests require the following environment variables to be set:
 *
 * <ul>
 *   <li>{@code AUTH0_DOMAIN} - The Auth0 domain (e.g., dev-12345.us.auth0.com)
 *   <li>{@code AUTH0_CLIENT_ID} - The client ID for the test client
 *   <li>{@code AUTH0_CLIENT_SECRET} - The client secret for the test client
 *   <li>{@code AUTH0_AUDIENCE} - The audience for the test client
 *   <li>{@code AUTH0_USERNAME} - A username for a test user
 *   <li>{@code AUTH0_PASSWORD} - The password for the test user
 *   <li>{@code AUTH0_REDIRECT_URI} - The redirect URI for the test client
 * </ul>
 *
 * Also, any human-to-machine flows (device code, authorization code) require the user running the
 * tests to follow the instructions printed on the console to complete the flow.
 */
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_DOMAIN_ENV, matches = ".+")
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_CLIENT_ID_ENV, matches = ".+")
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_CLIENT_SECRET_ENV, matches = ".+")
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_AUDIENCE_ENV, matches = ".+")
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_USERNAME_ENV, matches = ".+")
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_PASSWORD_ENV, matches = ".+")
@EnabledIfEnvironmentVariable(named = OAuth2AgentAuth0IT.AUTH0_REDIRECT_URI_ENV, matches = ".+")
public class OAuth2AgentAuth0IT {

  public static final String AUTH0_DOMAIN_ENV = "AUTH0_DOMAIN";
  public static final String AUTH0_CLIENT_ID_ENV = "AUTH0_CLIENT_ID";
  public static final String AUTH0_CLIENT_SECRET_ENV = "AUTH0_CLIENT_SECRET";
  public static final String AUTH0_AUDIENCE_ENV = "AUTH0_AUDIENCE";
  public static final String AUTH0_USERNAME_ENV = "AUTH0_USERNAME";
  public static final String AUTH0_PASSWORD_ENV = "AUTH0_PASSWORD";
  public static final String AUTH0_REDIRECT_URI_ENV = "AUTH0_REDIRECT_URI";

  @CartesianTest
  void basicTest(
      @EnumLike(includes = {"client_credentials", "password", "authorization_code"})
          GrantType initialGrantType,
      @EnumLike(includes = {"client_secret_basic", "client_secret_post"})
          ClientAuthenticationMethod authenticationMethod)
      throws Exception {
    try (TestEnvironment env = envBuilder(initialGrantType, authenticationMethod).build();
        OAuth2Agent agent = env.newAgent()) {
      // initial grant
      TokensResult initial = agent.authenticateInternal();
      introspectToken(initial.getTokens().getAccessToken(), env);
      // token refresh
      if (initialGrantType != GrantType.CLIENT_CREDENTIALS) {
        assertThat(initial.getTokens().getRefreshToken()).isNotNull();
        TokensResult refreshed = agent.refreshCurrentTokens(initial).toCompletableFuture().get();
        introspectToken(refreshed.getTokens().getAccessToken(), env);
        assertThat(refreshed.getTokens().getRefreshToken()).isNotNull();
      } else {
        assertThat(initial.getTokens().getRefreshToken()).isNull();
      }
    }
  }

  private void introspectToken(AccessToken accessToken, TestEnvironment env) throws ParseException {
    assertThat(accessToken).isNotNull();
    JWT jwt = JWTParser.parse(accessToken.getValue());
    assertThat(jwt).isNotNull();
    JWTClaimsSet claims = jwt.getJWTClaimsSet();
    assertThat(claims.getStringClaim("iss")).startsWith(env.getAuthorizationServerUrl().toString());
    assertThat(claims.getListClaim("aud"))
        .contains(env.getExtraRequestParameters().get("audience"));
    assertThat(claims.getStringClaim("azp")).contains(env.getClientId().getValue());
    assertThat(claims.getStringClaim("scope")).contains("catalog");
  }

  private static Builder envBuilder(
      GrantType initialGrantType, ClientAuthenticationMethod authenticationMethod) {

    URI issuerUrl = URI.create(System.getenv(AUTH0_DOMAIN_ENV));

    Scope scope =
        initialGrantType == GrantType.CLIENT_CREDENTIALS
            ? new Scope("catalog")
            : new Scope("catalog", "offline_access"); // request refresh token

    return TestEnvironment.builder()
        .serverRootUrl(issuerUrl)
        .authorizationServerUrl(issuerUrl)
        .grantType(initialGrantType)
        .clientAuthenticationMethod(authenticationMethod)
        .clientId(new ClientID(System.getenv(AUTH0_CLIENT_ID_ENV)))
        .clientSecret(new Secret(System.getenv(AUTH0_CLIENT_SECRET_ENV)))
        .scope(scope)
        .username(System.getenv(AUTH0_USERNAME_ENV))
        .password(new Secret(System.getenv(AUTH0_PASSWORD_ENV)))
        .extraRequestParameters(Map.of("audience", System.getenv(AUTH0_AUDIENCE_ENV)))
        .redirectUri(URI.create(System.getenv(AUTH0_REDIRECT_URI_ENV)))
        .unitTest(false)
        .forceInactiveUser(true) // login and consent must be performed manually
        .clock(Clock.systemUTC())
        .timeout(Duration.ofMinutes(10));
  }
}
