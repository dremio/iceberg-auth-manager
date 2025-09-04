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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class HttpConfigTest {

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties, HttpConfig expected, Throwable expectedThrowable) {
    if (properties != null && expected != null) {
      HttpConfig actual = HttpConfig.builder().from(properties).build();
      assertThat(actual).isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> HttpConfig.builder().from(properties));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(Map.of(), HttpConfig.DEFAULT, null),
        Arguments.of(PROPERTIES_1, CONFIG_1, null),
        Arguments.of(PROPERTIES_2, CONFIG_2, null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(HttpConfig base, Map<String, String> properties, HttpConfig expected) {
    HttpConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(HttpConfig.DEFAULT, PROPERTIES_1, CONFIG_1),
        Arguments.of(HttpConfig.DEFAULT, PROPERTIES_2, CONFIG_2),
        Arguments.of(CONFIG_1, Map.of(), CONFIG_1),
        Arguments.of(CONFIG_2, Map.of(), CONFIG_2),
        Arguments.of(CONFIG_1, PROPERTIES_2, CONFIG_2),
        Arguments.of(CONFIG_2, PROPERTIES_1, CONFIG_1),
        Arguments.of(CONFIG_1, PROPERTIES_3, HttpConfig.DEFAULT),
        Arguments.of(CONFIG_2, PROPERTIES_3, HttpConfig.DEFAULT));
  }

  private static final HttpConfig CONFIG_1 =
      HttpConfig.builder()
          .clientType(HttpClientType.APACHE)
          .readTimeout(Duration.ofMinutes(1))
          .connectionTimeout(Duration.ofMinutes(1))
          .headers(Map.of("custom", "value1"))
          .compressionEnabled(false)
          .sslProtocols(List.of("TLSv1.2"))
          .sslCipherSuites(List.of("TLS_AES_256_GCM_SHA384"))
          .sslHostnameVerificationEnabled(true)
          .sslTrustAll(true)
          .sslTrustStorePath(Path.of("/path/to/truststore"))
          .sslTrustStorePassword("truststore-password")
          .proxyHost("proxy.example.com")
          .proxyPort(8080)
          .proxyUsername("user")
          .proxyPassword("pass")
          .build();

  private static final HttpConfig CONFIG_2 =
      HttpConfig.builder()
          .clientType(HttpClientType.DEFAULT)
          .readTimeout(Duration.ofMinutes(2))
          .connectionTimeout(Duration.ofMinutes(2))
          .headers(Map.of("custom", "value2"))
          .compressionEnabled(true)
          .sslProtocols(List.of("TLSv1.3"))
          .sslCipherSuites(List.of("TLS_AES_128_GCM_SHA256"))
          .sslHostnameVerificationEnabled(false)
          .sslTrustAll(false)
          .sslTrustStorePath(Path.of("/path/to/truststore2"))
          .sslTrustStorePassword("truststore-password2")
          .proxyHost("proxy2.example.com")
          .proxyPort(8081)
          .proxyUsername("user2")
          .proxyPassword("pass2")
          .build();

  private static final Map<String, String> PROPERTIES_1 =
      ImmutableMap.<String, String>builder()
          .put(Http.CLIENT_TYPE, "apache")
          .put(Http.READ_TIMEOUT, "PT1M")
          .put(Http.CONNECT_TIMEOUT, "PT1M")
          .put(Http.HEADERS_PREFIX + "custom", "value1")
          .put(Http.COMPRESSION_ENABLED, "false")
          .put(Http.SSL_PROTOCOLS, "TLSv1.2")
          .put(Http.SSL_CIPHER_SUITES, "TLS_AES_256_GCM_SHA384")
          .put(Http.SSL_HOSTNAME_VERIFICATION_ENABLED, "true")
          .put(Http.SSL_TRUST_ALL, "true")
          .put(Http.SSL_TRUSTSTORE_PATH, "/path/to/truststore")
          .put(Http.SSL_TRUSTSTORE_PASSWORD, "truststore-password")
          .put(Http.PROXY_HOST, "proxy.example.com")
          .put(Http.PROXY_PORT, "8080")
          .put(Http.PROXY_USERNAME, "user")
          .put(Http.PROXY_PASSWORD, "pass")
          .build();

  private static final Map<String, String> PROPERTIES_2 =
      ImmutableMap.<String, String>builder()
          .put(Http.CLIENT_TYPE, "default")
          .put(Http.READ_TIMEOUT, "PT2M")
          .put(Http.CONNECT_TIMEOUT, "PT2M")
          .put(Http.HEADERS_PREFIX + "custom", "value2")
          .put(Http.COMPRESSION_ENABLED, "true")
          .put(Http.SSL_PROTOCOLS, "TLSv1.3")
          .put(Http.SSL_CIPHER_SUITES, "TLS_AES_128_GCM_SHA256")
          .put(Http.SSL_HOSTNAME_VERIFICATION_ENABLED, "false")
          .put(Http.SSL_TRUST_ALL, "false")
          .put(Http.SSL_TRUSTSTORE_PATH, "/path/to/truststore2")
          .put(Http.SSL_TRUSTSTORE_PASSWORD, "truststore-password2")
          .put(Http.PROXY_HOST, "proxy2.example.com")
          .put(Http.PROXY_PORT, "8081")
          .put(Http.PROXY_USERNAME, "user2")
          .put(Http.PROXY_PASSWORD, "pass2")
          .build();

  private static final Map<String, String> PROPERTIES_3 =
      ImmutableMap.<String, String>builder()
          .put(Http.CLIENT_TYPE, "")
          .put(Http.READ_TIMEOUT, "")
          .put(Http.CONNECT_TIMEOUT, "")
          .put(Http.HEADERS_PREFIX + "custom", "")
          .put(Http.COMPRESSION_ENABLED, "")
          .put(Http.SSL_PROTOCOLS, "")
          .put(Http.SSL_CIPHER_SUITES, "")
          .put(Http.SSL_HOSTNAME_VERIFICATION_ENABLED, "")
          .put(Http.SSL_TRUST_ALL, "")
          .put(Http.SSL_TRUSTSTORE_PATH, "")
          .put(Http.SSL_TRUSTSTORE_PASSWORD, "")
          .put(Http.PROXY_HOST, "")
          .put(Http.PROXY_PORT, "")
          .put(Http.PROXY_USERNAME, "")
          .put(Http.PROXY_PASSWORD, "")
          .build();
}
