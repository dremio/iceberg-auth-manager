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
package com.dremio.iceberg.authmgr.oauth2.config;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_CONFIG_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.REQUESTED_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_CONFIG_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN_TYPE;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TokenExchangeConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(TokenExchangeConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            TokenExchangeConfig.builder().subjectTokenType(TypedToken.URN_ID_TOKEN),
            singletonList(
                "subject token type must be urn:ietf:params:oauth:token-type:access_token when using dynamic subject token (rest.auth.oauth2.token-exchange.subject-token-type)")),
        Arguments.of(
            TokenExchangeConfig.builder()
                .actorTokenType(TypedToken.URN_ID_TOKEN)
                .actorTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://actor-token-endpoint.com/token")),
            singletonList(
                "actor token type must be urn:ietf:params:oauth:token-type:access_token when using dynamic actor token (rest.auth.oauth2.token-exchange.actor-token-type)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> config, TokenExchangeConfig expected, Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      TokenExchangeConfig actual = TokenExchangeConfig.builder().from(config).build();
      assertThat(actual).isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> TokenExchangeConfig.builder().from(config));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            Map.of(
                AUDIENCE,
                "audience",
                RESOURCE,
                "https://token-exchange.com/resource",
                SUBJECT_TOKEN,
                "subject-token",
                SUBJECT_TOKEN_TYPE,
                TypedToken.URN_ID_TOKEN.toString(),
                ACTOR_TOKEN,
                "actor-token",
                ACTOR_TOKEN_TYPE,
                TypedToken.URN_JWT.toString()),
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken("subject-token")
                .subjectTokenType(TypedToken.URN_ID_TOKEN)
                .actorToken("actor-token")
                .actorTokenType(TypedToken.URN_JWT)
                .build(),
            null),
        Arguments.of(
            Map.of(
                AUDIENCE,
                "audience",
                RESOURCE,
                "https://token-exchange.com/resource",
                SUBJECT_CONFIG_PREFIX + "token-endpoint",
                "https://subject-token-endpoint.com/token",
                ACTOR_CONFIG_PREFIX + "token-refresh.enabled",
                "false"),
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint.com/token"))
                .actorTokenConfig(Map.of(OAuth2Properties.TokenRefresh.ENABLED, "false"))
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(
      TokenExchangeConfig base, Map<String, String> properties, TokenExchangeConfig expected) {
    TokenExchangeConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        // empty base
        Arguments.of(
            TokenExchangeConfig.builder().build(),
            Map.of(
                AUDIENCE,
                "audience",
                RESOURCE,
                "https://token-exchange.com/resource",
                SUBJECT_TOKEN,
                "subject-token",
                SUBJECT_TOKEN_TYPE,
                TypedToken.URN_ID_TOKEN.toString(),
                ACTOR_TOKEN,
                "actor-token",
                ACTOR_TOKEN_TYPE,
                TypedToken.URN_JWT.toString(),
                REQUESTED_TOKEN_TYPE,
                TypedToken.URN_SAML2.toString(),
                SUBJECT_CONFIG_PREFIX + "token-endpoint",
                "https://subject-token-endpoint.com/token",
                ACTOR_CONFIG_PREFIX + "token-refresh.enabled",
                "false"),
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken("subject-token")
                .subjectTokenType(TypedToken.URN_ID_TOKEN)
                .actorToken("actor-token")
                .actorTokenType(TypedToken.URN_JWT)
                .requestedTokenType(TypedToken.URN_SAML2)
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint.com/token"))
                .actorTokenConfig(Map.of(OAuth2Properties.TokenRefresh.ENABLED, "false"))
                .build()),
        // empty properties
        Arguments.of(
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken("subject-token")
                .subjectTokenType(TypedToken.URN_ID_TOKEN)
                .actorToken("actor-token")
                .actorTokenType(TypedToken.URN_JWT)
                .requestedTokenType(TypedToken.URN_SAML2)
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint.com/token"))
                .actorTokenConfig(Map.of(OAuth2Properties.TokenRefresh.ENABLED, "false"))
                .build(),
            Map.of(),
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken("subject-token")
                .subjectTokenType(TypedToken.URN_ID_TOKEN)
                .actorToken("actor-token")
                .actorTokenType(TypedToken.URN_JWT)
                .requestedTokenType(TypedToken.URN_SAML2)
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint.com/token"))
                .actorTokenConfig(Map.of(OAuth2Properties.TokenRefresh.ENABLED, "false"))
                .build()),
        // non-empty base and properties
        Arguments.of(
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken("subject-token")
                .subjectTokenType(TypedToken.URN_ID_TOKEN)
                .actorToken("actor-token")
                .actorTokenType(TypedToken.URN_JWT)
                .requestedTokenType(TypedToken.URN_SAML2)
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint.com/token",
                        OAuth2Properties.Runtime.AGENT_NAME,
                        "subject-agent"))
                .actorTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://actor-token-endpoint.com/token",
                        OAuth2Properties.Runtime.AGENT_NAME,
                        "actor-agent"))
                .build(),
            ImmutableMap.builder()
                .put(AUDIENCE, "audience2")
                .put(RESOURCE, URI.create("https://token-exchange.com/resource2").toString())
                .put(SUBJECT_TOKEN, "subject-token2")
                .put(SUBJECT_TOKEN_TYPE, TypedToken.URN_SAML1.toString())
                .put(ACTOR_TOKEN, "actor-token2")
                .put(ACTOR_TOKEN_TYPE, TypedToken.URN_SAML2.toString())
                .put(REQUESTED_TOKEN_TYPE, TypedToken.URN_SAML1.toString())
                .put(
                    SUBJECT_CONFIG_PREFIX + "token-endpoint",
                    "https://subject-token-endpoint2.com/token")
                .put(SUBJECT_CONFIG_PREFIX + "token-refresh.enabled", "false")
                .put(
                    ACTOR_CONFIG_PREFIX + "token-endpoint",
                    "https://actor-token-endpoint2.com/token")
                .put(ACTOR_CONFIG_PREFIX + "token-refresh.enabled", "true")
                .build(),
            TokenExchangeConfig.builder()
                .audience("audience2")
                .resource(URI.create("https://token-exchange.com/resource2"))
                .subjectToken("subject-token2")
                .subjectTokenType(TypedToken.URN_SAML1)
                .actorToken("actor-token2")
                .actorTokenType(TypedToken.URN_SAML2)
                .requestedTokenType(TypedToken.URN_SAML1)
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint2.com/token",
                        OAuth2Properties.TokenRefresh.ENABLED,
                        "false",
                        OAuth2Properties.Runtime.AGENT_NAME,
                        "subject-agent"))
                .actorTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://actor-token-endpoint2.com/token",
                        OAuth2Properties.TokenRefresh.ENABLED,
                        "true",
                        OAuth2Properties.Runtime.AGENT_NAME,
                        "actor-agent"))
                .build()),
        // clear base
        Arguments.of(
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken("subject-token")
                .subjectTokenType(TypedToken.URN_ID_TOKEN)
                .actorToken("actor-token")
                .actorTokenType(TypedToken.URN_JWT)
                .requestedTokenType(TypedToken.URN_SAML2)
                .subjectTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://subject-token-endpoint.com/token",
                        OAuth2Properties.Runtime.AGENT_NAME,
                        "subject-agent"))
                .actorTokenConfig(
                    Map.of(
                        OAuth2Properties.Basic.TOKEN_ENDPOINT,
                        "https://actor-token-endpoint.com/token",
                        OAuth2Properties.Runtime.AGENT_NAME,
                        "actor-agent"))
                .build(),
            ImmutableMap.builder()
                .put(AUDIENCE, "")
                .put(RESOURCE, "")
                .put(SUBJECT_TOKEN, "")
                .put(SUBJECT_TOKEN_TYPE, "")
                .put(ACTOR_TOKEN, "")
                .put(ACTOR_TOKEN_TYPE, "")
                .put(REQUESTED_TOKEN_TYPE, "")
                .put(SUBJECT_CONFIG_PREFIX + "token-endpoint", "")
                .put(SUBJECT_CONFIG_PREFIX + "runtime.agent-name", "")
                .put(ACTOR_CONFIG_PREFIX + "token-endpoint", "")
                .put(ACTOR_CONFIG_PREFIX + "runtime.agent-name", "")
                .build(),
            TokenExchangeConfig.DEFAULT));
  }
}
