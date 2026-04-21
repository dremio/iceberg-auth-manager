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
package com.dremio.iceberg.authmgr.oauth2.jwtbearer;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ASSERTION_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.JwtBearerConfig;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AssertionSupplierTest {

  @Test
  void testSupplyAssertionAsyncStatic() {
    OAuth2Config config = createMainConfig(ASSERTION_TOKEN, null, Map.of());
    try (AssertionSupplier supplier = createSupplier(config)) {
      CompletionStage<String> stage = supplier.supplyAssertionAsync();
      assertThat(stage).isCompleted();
      assertThat(stage.toCompletableFuture().join()).isEqualTo(ASSERTION_TOKEN);
    }
  }

  @Test
  void testSupplyAssertionAsyncDynamic() {
    OAuth2Config config =
        createMainConfig(
            null,
            null,
            Map.of(
                BasicConfig.GRANT_TYPE,
                GrantType.CLIENT_CREDENTIALS.getValue(),
                BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                BasicConfig.CLIENT_ID,
                "test-client",
                BasicConfig.CLIENT_SECRET,
                "test-secret"));
    try (AssertionSupplier supplier = createSupplier(config)) {
      CompletionStage<String> stage = supplier.supplyAssertionAsync();
      assertThat(stage).isNotCompleted();
    }
  }

  @Test
  @SuppressWarnings("resource")
  void testValidate() {
    OAuth2Config config = createInvalidMainConfig();
    assertThatIllegalArgumentException()
        .isThrownBy(() -> createSupplier(config))
        .withMessage("Assertion is required");
  }

  @Test
  void testSupplyAssertionAsyncFromFile(@TempDir Path tempDir) throws Exception {
    Path assertionFile = tempDir.resolve("assertion.txt");
    Files.writeString(assertionFile, "  " + ASSERTION_TOKEN + "  ");
    OAuth2Config config = createMainConfig(null, assertionFile, Map.of());
    try (AssertionSupplier supplier = createSupplier(config)) {
      CompletionStage<String> stage = supplier.supplyAssertionAsync();
      assertThat(stage).isCompleted();
      assertThat(stage.toCompletableFuture().join()).isEqualTo(ASSERTION_TOKEN);
    }
  }

  private static OAuth2Config createMainConfig(
      String assertion, Path assertionFile, Map<String, String> assertionConfig) {
    return OAuth2Config.from(createProperties(assertion, assertionFile, assertionConfig));
  }

  private static OAuth2Config createInvalidMainConfig() {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withSources(
                new MapBackedConfigSource(
                    "catalog properties", createProperties(null, null, Map.of()), 200) {})
            .withMapping(OAuth2Config.class)
            .build();
    return smallRyeConfig.getConfigMapping(OAuth2Config.class);
  }

  private static Map<String, String> createProperties(
      String assertion, Path assertionFile, Map<String, String> assertionConfig) {
    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();

    builder.put(PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.JWT_BEARER.getValue());
    builder.put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token");
    builder.put(PREFIX + '.' + BasicConfig.CLIENT_ID, "test-client");
    builder.put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "test-secret");

    assertionConfig.forEach(
        (k, v) ->
            builder.put(JwtBearerConfig.PREFIX + '.' + JwtBearerConfig.ASSERTION + '.' + k, v));

    if (assertion != null) {
      builder.put(JwtBearerConfig.PREFIX + '.' + JwtBearerConfig.ASSERTION, assertion);
    }
    if (assertionFile != null) {
      builder.put(
          JwtBearerConfig.PREFIX + '.' + JwtBearerConfig.ASSERTION_FILE, assertionFile.toString());
    }

    return builder.build();
  }

  private static AssertionSupplier createSupplier(OAuth2Config config) {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    return AssertionSupplier.create(config, OAuth2AgentRuntime.of(executor));
  }
}
