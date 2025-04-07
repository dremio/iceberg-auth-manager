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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokens;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ImpersonationConfig;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ImpersonatingTokenExchangeFlowTest {

  private final Tokens currentTokens =
      Tokens.of(
          AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME),
          RefreshToken.of("refresh_initial", REFRESH_TOKEN_EXPIRATION_TIME));

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void fetchNewTokensDistinctServers(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .impersonationEnabled(true)
                .distinctImpersonationServer(true)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        Flow flow = env.newImpersonationFlow()) {
      Tokens tokens = flow.fetchNewTokens(currentTokens);
      assertTokens(tokens, "access_impersonated", "refresh_initial");
    }
  }

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void fetchNewTokensSameServer(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .impersonationEnabled(true)
                .distinctImpersonationServer(false)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        Flow flow = env.newImpersonationFlow()) {
      Tokens tokens = flow.fetchNewTokens(currentTokens);
      assertTokens(tokens, "access_impersonated", "refresh_initial");
    }
  }

  @Test
  void getResolvedTokenEndpoint() {
    // should use token endpoint from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .impersonationEnabled(true)
                .distinctImpersonationServer(true)
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getResolvedTokenEndpoint()).isEqualTo(env.getImpersonationTokenEndpoint());
    }
    // should use token endpoint from basic config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .impersonationEnabled(true)
                .distinctImpersonationServer(false)
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getResolvedTokenEndpoint()).isEqualTo(env.getTokenEndpoint());
    }
    // should use token endpoint from impersonation config (discovery disabled)
    try (TestEnvironment env =
            TestEnvironment.builder()
                .impersonationEnabled(true)
                .distinctImpersonationServer(true)
                .discoveryEnabled(false)
                .impersonationDiscoveryEnabled(false)
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getResolvedTokenEndpoint()).isEqualTo(env.getImpersonationTokenEndpoint());
    }
    // should use token endpoint from basic config (discovery enabled)
    try (TestEnvironment env =
            TestEnvironment.builder()
                .impersonationEnabled(true)
                .distinctImpersonationServer(false)
                .discoveryEnabled(false)
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getResolvedTokenEndpoint()).isEqualTo(env.getTokenEndpoint());
    }
  }

  @Test
  void getExtraRequestParameters() {
    // should use extra request parameters from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .clientId(CLIENT_ID1)
                        .extraRequestParameters(Map.of("key1", "value1"))
                        .build())
                .impersonationConfig(
                    ImpersonationConfig.builder()
                        .extraRequestParameters(Map.of("key2", "value2"))
                        .build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getExtraRequestParameters()).isEqualTo(Map.of("key2", "value2"));
    }
    // should use empty extra request parameters from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .clientId(CLIENT_ID1)
                        .extraRequestParameters(Map.of("key1", "value1"))
                        .build())
                .impersonationConfig(
                    ImpersonationConfig.builder().extraRequestParameters(Map.of()).build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getExtraRequestParameters()).isEqualTo(Map.of());
    }
    // should use extra request parameters from basic config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .clientId(CLIENT_ID1)
                        .extraRequestParameters(Map.of("key1", "value1"))
                        .build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getExtraRequestParameters()).isEqualTo(Map.of("key1", "value1"));
    }
  }

  @Test
  void getScopesAsString() {
    // should use scopes from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .clientId(CLIENT_ID1)
                        .scopes(List.of("scope1"))
                        .build())
                .impersonationConfig(
                    ImpersonationConfig.builder().scopes(List.of("scope2", "scope3")).build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getScopesAsString()).contains("scope2 scope3");
    }
    // should use empty scopes from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .clientId(CLIENT_ID1)
                        .scopes(List.of("scope1"))
                        .build())
                .impersonationConfig(ImpersonationConfig.builder().scopes(List.of()).build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getScopesAsString()).isEmpty();
    }
    // should use scopes from basic config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .clientId(CLIENT_ID1)
                        .scopes(List.of("scope1", "scope2"))
                        .build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getScopesAsString()).contains("scope1 scope2");
    }
  }

  @Test
  void getServiceAccount() {
    // should use client credentials from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .clientId(CLIENT_ID1)
                        .clientSecret(CLIENT_SECRET1)
                        .build())
                .impersonationConfig(
                    ImpersonationConfig.builder()
                        .clientId(CLIENT_ID2)
                        .clientSecret(CLIENT_SECRET2)
                        .build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getServiceAccount().getClientId()).contains(CLIENT_ID2);
      assertThat(flow.getServiceAccount().getClientSecret())
          .isPresent()
          .hasValueSatisfying(secret -> assertThat(secret.getSecret()).isEqualTo(CLIENT_SECRET2));
    }
    // should use client credentials from impersonation config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .clientId(CLIENT_ID1)
                        .clientSecret(CLIENT_SECRET1)
                        .build())
                .impersonationConfig(ImpersonationConfig.builder().clientId(CLIENT_ID2).build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getServiceAccount().getClientId()).contains(CLIENT_ID2);
      assertThat(flow.getServiceAccount().getClientSecret()).isNotPresent();
    }
    // should use client credentials from basic config
    try (TestEnvironment env =
            TestEnvironment.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .issuerUrl(URI.create("http://localhost"))
                        .clientId(CLIENT_ID1)
                        .clientSecret(CLIENT_SECRET1)
                        .build())
                .build();
        ImpersonatingTokenExchangeFlow flow =
            (ImpersonatingTokenExchangeFlow) env.newImpersonationFlow()) {
      assertThat(flow.getServiceAccount().getClientId()).contains(CLIENT_ID1);
      assertThat(flow.getServiceAccount().getClientSecret())
          .isPresent()
          .hasValueSatisfying(secret -> assertThat(secret.getSecret()).isEqualTo(CLIENT_SECRET1));
    }
  }
}
