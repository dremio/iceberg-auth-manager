/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.config;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_ID;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_SECRET;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.EXTRA_PARAMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.SCOPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.TOKEN_ENDPOINT;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ImpersonationConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(ImpersonationConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            ImpersonationConfig.builder().issuerUrl(URI.create("/realms/master")),
            singletonList(
                "Impersonation issuer URL must not be relative (rest.auth.oauth2.impersonation.issuer-url)")),
        Arguments.of(
            ImpersonationConfig.builder().issuerUrl(URI.create("https://example.com?query")),
            singletonList(
                "Impersonation issuer URL must not have a query part (rest.auth.oauth2.impersonation.issuer-url)")),
        Arguments.of(
            ImpersonationConfig.builder().issuerUrl(URI.create("https://example.com#fragment")),
            singletonList(
                "Impersonation issuer URL must not have a fragment part (rest.auth.oauth2.impersonation.issuer-url)")),
        Arguments.of(
            ImpersonationConfig.builder().tokenEndpoint(URI.create("https://example.com?query")),
            singletonList(
                "Impersonation token endpoint must not have a query part (rest.auth.oauth2.impersonation.token-endpoint)")),
        Arguments.of(
            ImpersonationConfig.builder().tokenEndpoint(URI.create("https://example.com#fragment")),
            singletonList(
                "Impersonation token endpoint must not have a fragment part (rest.auth.oauth2.impersonation.token-endpoint)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> config, ImpersonationConfig expected, Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      ImpersonationConfig actual = ImpersonationConfig.builder().from(config).build();
      assertThat(actual).usingRecursiveComparison().isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> ImpersonationConfig.builder().from(config));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            ImmutableMap.builder()
                .put(ENABLED, "true")
                .put(ISSUER_URL, "https://token-exchange.com/")
                .put(TOKEN_ENDPOINT, "https://token-exchange.com/")
                .put(CLIENT_ID, "token-exchange-client-id")
                .put(CLIENT_SECRET, "token-exchange-client-secret")
                .put(SCOPE, "scope1 scope2")
                .put(EXTRA_PARAMS_PREFIX + "extra1", "param1")
                .put(EXTRA_PARAMS_PREFIX + "extra2", "param 2")
                .put(EXTRA_PARAMS_PREFIX + "extra3", "") // empty
                .put(EXTRA_PARAMS_PREFIX, "") // malformed
                .build(),
            ImpersonationConfig.builder()
                .enabled(true)
                .issuerUrl(URI.create("https://token-exchange.com/"))
                .tokenEndpoint(URI.create("https://token-exchange.com/"))
                .clientId("token-exchange-client-id")
                .clientSecret("token-exchange-client-secret")
                .scopes(List.of("scope1", "scope2"))
                .extraRequestParameters(Map.of("extra1", "param1", "extra2", "param 2"))
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(
      ImpersonationConfig base, Map<String, String> properties, ImpersonationConfig expected) {
    ImpersonationConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            ImpersonationConfig.builder().build(),
            ImmutableMap.builder()
                .put(ENABLED, "true")
                .put(ISSUER_URL, "https://token-exchange.com/")
                .put(TOKEN_ENDPOINT, "https://token-exchange.com/")
                .put(CLIENT_ID, TestConstants.CLIENT_ID1)
                .put(CLIENT_SECRET, TestConstants.CLIENT_SECRET1)
                .put(SCOPE, TestConstants.SCOPE1)
                .put(EXTRA_PARAMS_PREFIX + "extra1", "param1")
                .put(EXTRA_PARAMS_PREFIX + "extra2", "param2")
                .build(),
            ImpersonationConfig.builder()
                .enabled(true)
                .issuerUrl(URI.create("https://token-exchange.com/"))
                .tokenEndpoint(URI.create("https://token-exchange.com/"))
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(TestConstants.CLIENT_SECRET1)
                .scopes(List.of(TestConstants.SCOPE1))
                .extraRequestParameters(Map.of("extra1", "param1", "extra2", "param2"))
                .build()),
        Arguments.of(
            ImpersonationConfig.builder()
                .enabled(true)
                .issuerUrl(URI.create("https://token-exchange.com/"))
                .tokenEndpoint(URI.create("https://token-exchange.com/"))
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(TestConstants.CLIENT_SECRET1)
                .scopes(List.of(TestConstants.SCOPE1))
                .extraRequestParameters(Map.of("extra1", "param1", "extra2", "param2"))
                .build(),
            Map.of(),
            ImpersonationConfig.builder()
                .enabled(true)
                .issuerUrl(URI.create("https://token-exchange.com/"))
                .tokenEndpoint(URI.create("https://token-exchange.com/"))
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(TestConstants.CLIENT_SECRET1)
                .scopes(List.of(TestConstants.SCOPE1))
                .extraRequestParameters(Map.of("extra1", "param1", "extra2", "param2"))
                .build()),
        Arguments.of(
            ImpersonationConfig.builder()
                .enabled(false)
                .issuerUrl(URI.create("https://token-exchange.com/"))
                .tokenEndpoint(URI.create("https://token-exchange.com/"))
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(TestConstants.CLIENT_SECRET1)
                .scopes(List.of(TestConstants.SCOPE1))
                .extraRequestParameters(Map.of("extra1", "param1", "extra2", "param2"))
                .build(),
            ImmutableMap.builder()
                .put(ENABLED, "true")
                .put(ISSUER_URL, "https://token-exchange2.com/")
                .put(TOKEN_ENDPOINT, "https://token-exchange2.com/")
                .put(CLIENT_ID, TestConstants.CLIENT_ID2)
                .put(CLIENT_SECRET, TestConstants.CLIENT_SECRET2)
                .put(SCOPE, TestConstants.SCOPE2)
                .put(EXTRA_PARAMS_PREFIX + "extra2", "param2")
                .put(EXTRA_PARAMS_PREFIX + "extra3", "param3")
                .build(),
            ImpersonationConfig.builder()
                .enabled(true)
                .issuerUrl(URI.create("https://token-exchange2.com/"))
                .tokenEndpoint(URI.create("https://token-exchange2.com/"))
                .clientId(TestConstants.CLIENT_ID2)
                .clientSecret(TestConstants.CLIENT_SECRET2)
                .scopes(List.of(TestConstants.SCOPE2))
                .extraRequestParameters(
                    Map.of("extra1", "param1", "extra2", "param2", "extra3", "param3"))
                .build()),
        Arguments.of(
            ImpersonationConfig.builder()
                .enabled(false)
                .issuerUrl(URI.create("https://token-exchange.com/"))
                .tokenEndpoint(URI.create("https://token-exchange.com/"))
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(TestConstants.CLIENT_SECRET1)
                .scopes(List.of(TestConstants.SCOPE1))
                .extraRequestParameters(Map.of("extra1", "param1", "extra2", "param2"))
                .build(),
            ImmutableMap.builder()
                .put(ISSUER_URL, "")
                .put(TOKEN_ENDPOINT, "")
                .put(CLIENT_ID, "")
                .put(CLIENT_SECRET, "")
                .put(SCOPE, "")
                .put(EXTRA_PARAMS_PREFIX + "extra2", "")
                .put(EXTRA_PARAMS_PREFIX + "extra3", "")
                .build(),
            ImpersonationConfig.builder()
                .extraRequestParameters(Map.of("extra1", "param1"))
                .build()));
  }
}
