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

import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig.SUBJECT_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.id.Audience;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TokenExchangeConfigTest {

  @Test
  void testAudienceEmpty() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + SUBJECT_TOKEN, "subject-token")
            .build();
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenExchangeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenExchangeConfig config = smallRyeConfig.getConfigMapping(TokenExchangeConfig.class, PREFIX);
    assertThat(config.getAudience()).isEmpty();
  }

  @Test
  void testSingleAudience() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + SUBJECT_TOKEN, "subject-token")
            .put(PREFIX + '.' + AUDIENCE, "https://example.com/resource")
            .build();
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenExchangeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenExchangeConfig config = smallRyeConfig.getConfigMapping(TokenExchangeConfig.class, PREFIX);
    assertThat(config.getAudience())
        .contains(List.of(new Audience("https://example.com/resource")));
  }

  @Test
  void testMultipleAudiences() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + SUBJECT_TOKEN, "subject-token")
            .put(
                PREFIX + '.' + AUDIENCE,
                "https://example.com/resource1,https://example.com/resource2")
            .build();
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenExchangeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenExchangeConfig config = smallRyeConfig.getConfigMapping(TokenExchangeConfig.class, PREFIX);
    assertThat(config.getAudience())
        .contains(
            List.of(
                new Audience("https://example.com/resource1"),
                new Audience("https://example.com/resource2")));
  }
}
