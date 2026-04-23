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

import static com.dremio.iceberg.authmgr.oauth2.config.DpopConfig.PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.nimbusds.jose.JWSAlgorithm;
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

class DpopConfigTest {

  static Path tempFile;

  @BeforeAll
  static void createFile(@TempDir Path tempDir) throws IOException {
    tempFile = Files.createTempFile(tempDir, "dpop-key", ".pem");
  }

  private static DpopConfig load(Map<String, String> properties) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(DpopConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    return smallRyeConfig.getConfigMapping(DpopConfig.class, PREFIX);
  }

  @Test
  void testDefaults() {
    DpopConfig config = load(Map.of());
    assertThat(config.isEnabled()).isFalse();
    assertThat(config.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    assertThat(config.getPrivateKey()).isEmpty();
    assertThat(config.getPublicKey()).isEmpty();
  }

  @Test
  void testEnabledEphemeral() {
    DpopConfig config = load(Map.of(PREFIX + '.' + DpopConfig.ENABLED, "true"));
    assertThat(config.isEnabled()).isTrue();
    assertThat(config.getPrivateKey()).isEmpty();
    config.validate();
  }

  @Test
  void testEnabledWithPrivateKey() {
    DpopConfig config =
        load(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED, "true",
                PREFIX + '.' + DpopConfig.ALGORITHM, "RS256",
                PREFIX + '.' + DpopConfig.PRIVATE_KEY, tempFile.toString()));
    assertThat(config.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    assertThat(config.getPrivateKey()).hasValue(tempFile);
    config.validate();
  }

  @Test
  void testEnabledWithPrivateAndPublicKey() {
    DpopConfig config =
        load(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED,
                "true",
                PREFIX + '.' + DpopConfig.ALGORITHM,
                "ES256",
                PREFIX + '.' + DpopConfig.PRIVATE_KEY,
                tempFile.toString(),
                PREFIX + '.' + DpopConfig.PUBLIC_KEY,
                tempFile.toString()));
    assertThat(config.getPrivateKey()).hasValue(tempFile);
    assertThat(config.getPublicKey()).hasValue(tempFile);
    config.validate();
  }

  @Test
  void testDisabledSkipsValidation() {
    DpopConfig config =
        load(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED, "false",
                PREFIX + '.' + DpopConfig.ALGORITHM, "HS256",
                PREFIX + '.' + DpopConfig.PRIVATE_KEY, "/nonexistent"));
    config.validate();
  }

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    DpopConfig config = load(properties);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED, "true",
                PREFIX + '.' + DpopConfig.ALGORITHM, "HS256"),
            List.of(
                "DPoP: unsupported JWS algorithm 'HS256', must be an RSA or EC algorithm "
                    + "(rest.auth.oauth2.dpop.algorithm)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED, "true",
                PREFIX + '.' + DpopConfig.ALGORITHM, "EdDSA"),
            List.of(
                "DPoP: unsupported JWS algorithm 'EdDSA', must be an RSA or EC algorithm "
                    + "(rest.auth.oauth2.dpop.algorithm)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED, "true",
                PREFIX + '.' + DpopConfig.PRIVATE_KEY, "/invalid/path"),
            List.of(
                "DPoP: private key path '/invalid/path' is not a file or is not readable "
                    + "(rest.auth.oauth2.dpop.private-key)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + DpopConfig.ENABLED, "true",
                PREFIX + '.' + DpopConfig.PUBLIC_KEY, "/invalid/pub"),
            List.of(
                "DPoP: public key path '/invalid/pub' is not a file or is not readable "
                    + "(rest.auth.oauth2.dpop.public-key)")));
  }
}
