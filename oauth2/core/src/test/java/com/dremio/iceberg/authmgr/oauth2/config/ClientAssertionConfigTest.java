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

import static com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig.PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ClientAssertionConfigTest {

  @TempDir static Path tempDir;

  static Path tempFile;

  @BeforeAll
  static void createFile() throws IOException {
    tempFile = Files.createTempFile(tempDir, "private-key", ".pem");
  }

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(ClientAssertionConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    ClientAssertionConfig config =
        smallRyeConfig.getConfigMapping(ClientAssertionConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(PREFIX + '.' + ClientAssertionConfig.ALGORITHM, "RS256"),
            List.of(
                "client assertion: JWS signing algorithm 'RS256' requires a private key "
                    + "(rest.auth.oauth2.client-assertion.jwt.algorithm / rest.auth.oauth2.client-assertion.jwt.private-key)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + ClientAssertionConfig.ALGORITHM,
                "HS256",
                PREFIX + '.' + ClientAssertionConfig.PRIVATE_KEY,
                tempFile.toString()),
            List.of(
                "client assertion: private key must not be set for JWS algorithm 'HS256' "
                    + "(rest.auth.oauth2.client-assertion.jwt.algorithm / rest.auth.oauth2.client-assertion.jwt.private-key)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + ClientAssertionConfig.ALGORITHM,
                "RSA_SHA256",
                PREFIX + '.' + ClientAssertionConfig.PRIVATE_KEY,
                tempFile.toString()),
            List.of(
                "client assertion: unsupported JWS algorithm 'RSA_SHA256', must be one of: "
                    + "'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES256K', 'ES384', 'ES512', 'EdDSA', 'Ed25519', 'Ed448' "
                    + "(rest.auth.oauth2.client-assertion.jwt.algorithm)")),
        Arguments.of(
            Map.of(PREFIX + '.' + ClientAssertionConfig.PRIVATE_KEY, "/invalid/path"),
            List.of(
                "client assertion: private key path '/invalid/path' is not a file or is not readable "
                    + "(rest.auth.oauth2.client-assertion.jwt.private-key)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        Map.of(
            PREFIX + '.' + ClientAssertionConfig.ISSUER, "https://example.com",
            PREFIX + '.' + ClientAssertionConfig.SUBJECT, "subject",
            PREFIX + '.' + ClientAssertionConfig.AUDIENCE, "audience",
            PREFIX + '.' + ClientAssertionConfig.TOKEN_LIFESPAN, "PT1M",
            PREFIX + '.' + ClientAssertionConfig.ALGORITHM, "RS256",
            PREFIX + '.' + ClientAssertionConfig.PRIVATE_KEY, tempFile.toString(),
            PREFIX + '.' + ClientAssertionConfig.EXTRA_CLAIMS + ".extra1", "value1");
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(ClientAssertionConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    ClientAssertionConfig config =
        smallRyeConfig.getConfigMapping(ClientAssertionConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}
