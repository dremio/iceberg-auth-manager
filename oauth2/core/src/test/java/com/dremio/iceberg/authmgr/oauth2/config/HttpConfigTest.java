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

import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.CLIENT_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.COMPRESSION_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.CONNECT_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.HEADERS;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.PROXY_HOST;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.PROXY_PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.PROXY_PORT;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.PROXY_USERNAME;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.READ_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.SSL_CIPHER_SUITES;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.SSL_HOSTNAME_VERIFICATION_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.SSL_PROTOCOLS;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.SSL_TRUSTSTORE_PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.SSL_TRUSTSTORE_PATH;
import static com.dremio.iceberg.authmgr.oauth2.config.HttpConfig.SSL_TRUST_ALL;
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

class HttpConfigTest {

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
            .withMapping(HttpConfig.class, HttpConfig.PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    HttpConfig config = smallRyeConfig.getConfigMapping(HttpConfig.class, HttpConfig.PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(HttpConfig.PREFIX + '.' + SSL_TRUSTSTORE_PATH, "/invalid/path"),
            singletonList(
                "http: SSL truststore path '/invalid/path' is not a file or is not readable (rest.auth.oauth2.http.ssl.trust-store.path)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + CLIENT_TYPE, "APACHE")
            .put(PREFIX + '.' + READ_TIMEOUT, "PT1M")
            .put(PREFIX + '.' + CONNECT_TIMEOUT, "PT1M")
            .put(PREFIX + '.' + HEADERS + ".custom", "value1")
            .put(PREFIX + '.' + COMPRESSION_ENABLED, "true")
            .put(PREFIX + '.' + SSL_PROTOCOLS, "TLSv1.2")
            .put(PREFIX + '.' + SSL_CIPHER_SUITES, "TLS_AES_256_GCM_SHA384")
            .put(PREFIX + '.' + SSL_HOSTNAME_VERIFICATION_ENABLED, "true")
            .put(PREFIX + '.' + SSL_TRUST_ALL, "true")
            .put(PREFIX + '.' + SSL_TRUSTSTORE_PATH, tempFile.toString())
            .put(PREFIX + '.' + SSL_TRUSTSTORE_PASSWORD, "truststore-password")
            .put(PREFIX + '.' + PROXY_HOST, "proxy.example.com")
            .put(PREFIX + '.' + PROXY_PORT, "8080")
            .put(PREFIX + '.' + PROXY_USERNAME, "user")
            .put(PREFIX + '.' + PROXY_PASSWORD, "pass")
            .build();
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(HttpConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    HttpConfig config = smallRyeConfig.getConfigMapping(HttpConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}
