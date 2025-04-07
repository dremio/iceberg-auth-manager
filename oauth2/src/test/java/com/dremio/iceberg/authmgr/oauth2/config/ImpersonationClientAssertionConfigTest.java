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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.ALGORITHM;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.EXTRA_CLAIMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.ISSUER;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.PRIVATE_KEY;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.SUBJECT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ImpersonationClientAssertion.TOKEN_LIFESPAN;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.auth.JwtSigningAlgorithm;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ImpersonationClientAssertionConfigTest {

  @TempDir static Path tempDir;

  static Path tempFile;

  @BeforeAll
  static void createFile() throws IOException {
    tempFile = Files.createTempFile(tempDir, "private-key", ".pem");
  }

  @ParameterizedTest
  @MethodSource
  void testValidate(ImpersonationClientAssertionConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            ImpersonationClientAssertionConfig.builder().algorithm(JwtSigningAlgorithm.RSA_SHA256),
            singletonList(
                "impersonation client assertion: JWT signing algorithm RS256 requires a private key (rest.auth.oauth2.impersonation.client-assertion.jwt.algorithm / rest.auth.oauth2.impersonation.client-assertion.jwt.private-key)")),
        Arguments.of(
            ImpersonationClientAssertionConfig.builder().privateKey(Paths.get("/invalid/path")),
            singletonList(
                "impersonation client assertion: private key path '/invalid/path' is not a file or is not readable (rest.auth.oauth2.impersonation.client-assertion.jwt.private-key)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties,
      ImpersonationClientAssertionConfig expected,
      Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      ImpersonationClientAssertionConfig actual =
          ImpersonationClientAssertionConfig.builder().from(properties).build();
      assertThat(actual).isEqualTo(expected);
    } else {
      Throwable actual =
          catchThrowable(() -> ImpersonationClientAssertionConfig.builder().from(properties));
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
                ISSUER,
                "https://example.com/token",
                SUBJECT,
                "subject",
                AUDIENCE,
                "audience",
                TOKEN_LIFESPAN,
                "PT1H",
                EXTRA_CLAIMS_PREFIX + "key1",
                "value1",
                ALGORITHM,
                "RS256",
                PRIVATE_KEY,
                tempFile.toString()),
            ImpersonationClientAssertionConfig.builder()
                .issuer("https://example.com/token")
                .subject("subject")
                .audience("audience")
                .tokenLifespan(Duration.ofHours(1))
                .extraClaims(Map.of("key1", "value1"))
                .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                .privateKey(tempFile)
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(
      ImpersonationClientAssertionConfig base,
      Map<String, String> properties,
      ImpersonationClientAssertionConfig expected) {
    ImpersonationClientAssertionConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            ImpersonationClientAssertionConfig.builder().build(),
            Map.of(
                ISSUER,
                "https://example.com/token",
                SUBJECT,
                "subject",
                AUDIENCE,
                "audience",
                TOKEN_LIFESPAN,
                "PT1H",
                EXTRA_CLAIMS_PREFIX + "key1",
                "value1",
                ALGORITHM,
                "RS256",
                PRIVATE_KEY,
                tempFile.toString()),
            ImpersonationClientAssertionConfig.builder()
                .issuer("https://example.com/token")
                .subject("subject")
                .audience("audience")
                .tokenLifespan(Duration.ofHours(1))
                .extraClaims(Map.of("key1", "value1"))
                .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                .privateKey(tempFile)
                .build()),
        Arguments.of(
            ImpersonationClientAssertionConfig.builder()
                .issuer("https://example.com/token")
                .subject("subject")
                .audience("audience")
                .tokenLifespan(Duration.ofHours(1))
                .extraClaims(Map.of("key1", "value1"))
                .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                .privateKey(tempFile)
                .build(),
            Map.of(),
            ImpersonationClientAssertionConfig.builder()
                .issuer("https://example.com/token")
                .subject("subject")
                .audience("audience")
                .tokenLifespan(Duration.ofHours(1))
                .extraClaims(Map.of("key1", "value1"))
                .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                .privateKey(tempFile)
                .build()),
        Arguments.of(
            ImpersonationClientAssertionConfig.builder()
                .issuer("https://example.com/token")
                .subject("subject")
                .audience("audience")
                .tokenLifespan(Duration.ofHours(1))
                .extraClaims(Map.of("key1", "value1"))
                .algorithm(JwtSigningAlgorithm.RSA_SHA256)
                .privateKey(tempFile)
                .build(),
            Map.of(
                ISSUER,
                "",
                SUBJECT,
                "",
                AUDIENCE,
                "",
                TOKEN_LIFESPAN,
                "",
                EXTRA_CLAIMS_PREFIX + "key1",
                "",
                ALGORITHM,
                "",
                PRIVATE_KEY,
                ""),
            ImpersonationClientAssertionConfig.builder().build()));
  }
}
