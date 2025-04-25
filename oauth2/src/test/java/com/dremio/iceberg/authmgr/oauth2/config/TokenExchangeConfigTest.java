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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.CURRENT_ACCESS_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProviders;
import java.net.URI;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TokenExchangeConfigTest {

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
                .subjectToken(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN))
                .actorToken(TypedToken.of("actor-token", TypedToken.URN_JWT))
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
                TypedToken.URN_JWT.toString()),
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN))
                .actorToken(TypedToken.of("actor-token", TypedToken.URN_JWT))
                .build()),
        Arguments.of(
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN))
                .actorToken(TypedToken.of("actor-token", TypedToken.URN_JWT))
                .build(),
            Map.of(),
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN))
                .actorToken(TypedToken.of("actor-token", TypedToken.URN_JWT))
                .build()),
        Arguments.of(
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN))
                .actorToken(TypedToken.of("actor-token", TypedToken.URN_JWT))
                .build(),
            Map.of(
                AUDIENCE,
                "audience2",
                RESOURCE,
                "https://token-exchange.com/resource2",
                SUBJECT_TOKEN,
                "subject-token2",
                SUBJECT_TOKEN_TYPE,
                TypedToken.URN_SAML1.toString(),
                ACTOR_TOKEN,
                "actor-token2",
                ACTOR_TOKEN_TYPE,
                TypedToken.URN_SAML2.toString()),
            TokenExchangeConfig.builder()
                .audience("audience2")
                .resource(URI.create("https://token-exchange.com/resource2"))
                .subjectToken(TypedToken.of("subject-token2", TypedToken.URN_SAML1))
                .actorToken(TypedToken.of("actor-token2", TypedToken.URN_SAML2))
                .build()),
        Arguments.of(
            TokenExchangeConfig.builder()
                .audience("audience")
                .resource(URI.create("https://token-exchange.com/resource"))
                .subjectToken(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN))
                .actorToken(TypedToken.of("actor-token", TypedToken.URN_JWT))
                .build(),
            Map.of(
                AUDIENCE,
                "",
                RESOURCE,
                "",
                SUBJECT_TOKEN,
                "",
                SUBJECT_TOKEN_TYPE,
                "",
                ACTOR_TOKEN,
                "",
                ACTOR_TOKEN_TYPE,
                ""),
            TokenExchangeConfig.builder().build()));
  }

  @Test
  void testTokenExchangeDefaultTokens() {
    Map<String, String> properties = Map.of();
    TokenExchangeConfig config = TokenExchangeConfig.builder().from(properties).build();
    TypedToken subjectToken =
        config
            .getSubjectTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(subjectToken.getPayload()).isEqualTo("dynamic-access");
    assertThat(subjectToken.getTokenType()).isEqualTo(TypedToken.URN_ACCESS_TOKEN);
    assertThat(config.getActorTokenProvider()).isSameAs(TokenProviders.NULL_TOKEN);
  }

  @Test
  void testTokenExchangeStaticTokens() {
    Map<String, String> properties =
        Map.of(
            SUBJECT_TOKEN,
            "static-subject",
            SUBJECT_TOKEN_TYPE,
            TypedToken.URN_SAML1.toString(),
            ACTOR_TOKEN,
            "static-actor",
            ACTOR_TOKEN_TYPE,
            TypedToken.URN_SAML2.toString());
    TokenExchangeConfig config = TokenExchangeConfig.builder().from(properties).build();
    TypedToken subjectToken =
        config
            .getSubjectTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(subjectToken.getPayload()).isEqualTo("static-subject");
    assertThat(subjectToken.getTokenType()).isEqualTo(TypedToken.URN_SAML1);
    TypedToken actorToken =
        config
            .getActorTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(actorToken.getPayload()).isEqualTo("static-actor");
    assertThat(actorToken.getTokenType()).isEqualTo(TypedToken.URN_SAML2);
  }

  @Test
  void testTokenExchangeDynamicTokens() {
    Map<String, String> properties =
        Map.of(SUBJECT_TOKEN, CURRENT_ACCESS_TOKEN, ACTOR_TOKEN, CURRENT_ACCESS_TOKEN);
    TokenExchangeConfig config = TokenExchangeConfig.builder().from(properties).build();
    TypedToken subjectToken =
        config
            .getSubjectTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(subjectToken.getPayload()).isEqualTo("dynamic-access");
    assertThat(subjectToken.getTokenType()).isEqualTo(TypedToken.URN_ACCESS_TOKEN);
    TypedToken actorToken =
        config
            .getActorTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(actorToken.getPayload()).isEqualTo("dynamic-access");
    assertThat(actorToken.getTokenType()).isEqualTo(TypedToken.URN_ACCESS_TOKEN);
  }

  @Test
  void testTokenExchangeDynamicTokens2() {
    // Only token types are provided, actual tokens are dynamically computed
    Map<String, String> properties =
        Map.of(
            SUBJECT_TOKEN_TYPE,
            TypedToken.URN_JWT.toString(),
            ACTOR_TOKEN_TYPE,
            TypedToken.URN_REFRESH_TOKEN.toString());
    TokenExchangeConfig config = TokenExchangeConfig.builder().from(properties).build();
    TypedToken subjectToken =
        config
            .getSubjectTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(subjectToken.getPayload()).isEqualTo("dynamic-access");
    assertThat(subjectToken.getTokenType()).isEqualTo(TypedToken.URN_JWT);
    TypedToken actorToken =
        config
            .getActorTokenProvider()
            .provideToken(AccessToken.of("dynamic-access", "Bearer", null));
    assertThat(actorToken.getPayload()).isEqualTo("dynamic-access");
    assertThat(actorToken.getTokenType()).isEqualTo(TypedToken.URN_REFRESH_TOKEN);
  }
}
