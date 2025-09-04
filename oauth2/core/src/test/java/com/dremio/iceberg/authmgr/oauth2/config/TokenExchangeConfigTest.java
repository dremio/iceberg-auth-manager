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

import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.ACTOR_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.ACTOR_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.DEFAULT_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.REQUESTED_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.SUBJECT_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.SUBJECT_TOKEN_TYPE;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.google.common.collect.ImmutableMap;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TokenExchangeConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenExchangeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenExchangeConfig config = smallRyeConfig.getConfigMapping(TokenExchangeConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(PREFIX + '.' + SUBJECT_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:id_token"),
            singletonList(
                "subject token type must be urn:ietf:params:oauth:token-type:access_token when using dynamic subject token (rest.auth.oauth2.token-exchange.subject-token-type)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + ACTOR_TOKEN_TYPE,
                "urn:ietf:params:oauth:token-type:id_token",
                PREFIX + '.' + ACTOR_TOKEN + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://actor-token-endpoint.com/token"),
            singletonList(
                "actor token type must be urn:ietf:params:oauth:token-type:access_token when using dynamic actor token (rest.auth.oauth2.token-exchange.actor-token-type)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + SUBJECT_TOKEN, "subject-token")
            .put(PREFIX + '.' + ACTOR_TOKEN, "actor-token")
            .put(PREFIX + '.' + SUBJECT_TOKEN_TYPE, DEFAULT_TOKEN_TYPE)
            .put(PREFIX + '.' + ACTOR_TOKEN_TYPE, DEFAULT_TOKEN_TYPE)
            .put(PREFIX + '.' + REQUESTED_TOKEN_TYPE, DEFAULT_TOKEN_TYPE)
            .put(PREFIX + '.' + RESOURCE, "https://example.com/resource")
            .put(PREFIX + '.' + AUDIENCE, "https://example.com/resource")
            .put(
                PREFIX + '.' + SUBJECT_TOKEN + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://subject-token-endpoint.com/token")
            .put(PREFIX + '.' + SUBJECT_TOKEN + '.' + BasicConfig.GRANT_TYPE, "client_credentials")
            .put(PREFIX + '.' + SUBJECT_TOKEN + '.' + BasicConfig.CLIENT_ID, "subject-client")
            .put(PREFIX + '.' + SUBJECT_TOKEN + '.' + BasicConfig.CLIENT_SECRET, "subject-secret")
            .put(PREFIX + '.' + SUBJECT_TOKEN + '.' + BasicConfig.SCOPE, "subject-scope")
            .put(
                PREFIX + '.' + ACTOR_TOKEN + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://actor-token-endpoint.com/token")
            .put(PREFIX + '.' + ACTOR_TOKEN + '.' + BasicConfig.GRANT_TYPE, "client_credentials")
            .put(PREFIX + '.' + ACTOR_TOKEN + '.' + BasicConfig.CLIENT_ID, "actor-client")
            .put(PREFIX + '.' + ACTOR_TOKEN + '.' + BasicConfig.CLIENT_SECRET, "actor-secret")
            .put(PREFIX + '.' + ACTOR_TOKEN + '.' + BasicConfig.SCOPE, "actor-scope")
            .build();
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenExchangeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenExchangeConfig config = smallRyeConfig.getConfigMapping(TokenExchangeConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}
