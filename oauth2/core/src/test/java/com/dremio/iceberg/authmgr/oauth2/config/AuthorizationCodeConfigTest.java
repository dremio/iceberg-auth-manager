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

import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.CALLBACK_BIND_HOST;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.CALLBACK_BIND_PORT;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.CALLBACK_CONTEXT_PATH;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.CALLBACK_HTTPS;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.ENDPOINT;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.PKCE_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.PKCE_METHOD;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.REDIRECT_URI;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.SSL_CIPHER_SUITES;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.SSL_KEYSTORE_ALIAS;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.SSL_KEYSTORE_PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.SSL_KEYSTORE_PATH;
import static com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig.SSL_PROTOCOLS;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.google.common.collect.ImmutableMap;
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

class AuthorizationCodeConfigTest {

  static Path tempFile;

  @BeforeAll
  static void createFile(@TempDir Path tempDir) throws IOException {
    tempFile = Files.createTempFile(tempDir, "private-key", ".pem");
  }

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(AuthorizationCodeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    AuthorizationCodeConfig config =
        smallRyeConfig.getConfigMapping(AuthorizationCodeConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(PREFIX + '.' + ENDPOINT, "/auth"),
            singletonList(
                "authorization code flow: authorization endpoint must not be relative (rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            Map.of(PREFIX + '.' + ENDPOINT, "https://example.com?query"),
            singletonList(
                "authorization code flow: authorization endpoint must not have a query part (rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            Map.of(PREFIX + '.' + ENDPOINT, "https://example.com#fragment"),
            singletonList(
                "authorization code flow: authorization endpoint must not have a fragment part (rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + ENDPOINT,
                "https://example.com",
                PREFIX + '.' + CALLBACK_BIND_PORT,
                "-1"),
            singletonList(
                "authorization code flow: callback bind port must be between 0 and 65535 (inclusive) (rest.auth.oauth2.auth-code.callback.bind-port)")),
        Arguments.of(
            Map.of(PREFIX + '.' + PKCE_METHOD, "PLAIN"),
            singletonList(
                "authorization code flow: code challenge method must be one of: 'plain', 'S256' (rest.auth.oauth2.auth-code.pkce.method)")),
        Arguments.of(
            Map.of(PREFIX + '.' + SSL_KEYSTORE_PATH, "/invalid/path"),
            singletonList(
                "authorization code flow: SSL keystore path '/invalid/path' is not a file or is not readable (rest.auth.oauth2.auth-code.ssl.key-store.path)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + ENDPOINT, "https://example.com/auth")
            .put(PREFIX + '.' + REDIRECT_URI, "https://example.com/callback")
            .put(PREFIX + '.' + CALLBACK_HTTPS, "true")
            .put(PREFIX + '.' + CALLBACK_BIND_HOST, "0.0.0.0")
            .put(PREFIX + '.' + CALLBACK_BIND_PORT, "8080")
            .put(PREFIX + '.' + CALLBACK_CONTEXT_PATH, "/callback")
            .put(PREFIX + '.' + PKCE_ENABLED, "true")
            .put(PREFIX + '.' + PKCE_METHOD, "S256")
            .put(PREFIX + '.' + SSL_KEYSTORE_PATH, tempFile.toString())
            .put(PREFIX + '.' + SSL_KEYSTORE_PASSWORD, "keystore-password")
            .put(PREFIX + '.' + SSL_KEYSTORE_ALIAS, "alias")
            .put(PREFIX + '.' + SSL_PROTOCOLS, "TLSv1.2")
            .put(PREFIX + '.' + SSL_CIPHER_SUITES, "TLS_AES_256_GCM_SHA384")
            .build();
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(AuthorizationCodeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    AuthorizationCodeConfig config =
        smallRyeConfig.getConfigMapping(AuthorizationCodeConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}
