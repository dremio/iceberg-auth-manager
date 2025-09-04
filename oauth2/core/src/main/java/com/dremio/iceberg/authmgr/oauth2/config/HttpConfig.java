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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.CLIENT_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.COMPRESSION_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.CONNECT_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.HEADERS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.PROXY_HOST;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.PROXY_PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.PROXY_PORT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.PROXY_USERNAME;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.READ_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.SSL_CIPHER_SUITES;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.SSL_HOSTNAME_VERIFICATION_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.SSL_PROTOCOLS;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.SSL_TRUSTSTORE_PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.SSL_TRUSTSTORE_PATH;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Http.SSL_TRUST_ALL;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface HttpConfig {

  HttpConfig DEFAULT = builder().build();

  /**
   * The HTTP client implementation to use for network communication. Defaults to {@link
   * HttpClientType#DEFAULT}.
   *
   * @see OAuth2Properties.Http#CLIENT_TYPE
   */
  @Value.Default
  default HttpClientType getClientType() {
    return HttpClientType.DEFAULT;
  }

  /**
   * The read timeout for HTTP requests. Defaults to {@link
   * OAuth2Properties.Http#DEFAULT_READ_TIMEOUT}.
   *
   * @see OAuth2Properties.Http#READ_TIMEOUT
   */
  @Value.Default
  default Duration getReadTimeout() {
    return ConfigConstants.HTTP_DEFAULT_READ_TIMEOUT;
  }

  /**
   * The connection timeout for HTTP requests. Defaults to {@link
   * OAuth2Properties.Http#DEFAULT_CONNECT_TIMEOUT}.
   *
   * @see OAuth2Properties.Http#CONNECT_TIMEOUT
   */
  @Value.Default
  default Duration getConnectionTimeout() {
    return ConfigConstants.HTTP_DEFAULT_CONNECT_TIMEOUT;
  }

  /**
   * HTTP headers to include in each HTTP request.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#HEADERS_PREFIX
   */
  Map<String, String> getHeaders();

  /**
   * Proxy host to use for HTTP requests.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#PROXY_HOST
   */
  Optional<String> getProxyHost();

  /**
   * Proxy port to use for HTTP requests.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#PROXY_PORT
   */
  OptionalInt getProxyPort();

  /**
   * Proxy username to use for HTTP requests.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#PROXY_USERNAME
   */
  Optional<String> getProxyUsername();

  /**
   * Proxy password to use for HTTP requests.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#PROXY_PASSWORD
   */
  Optional<String> getProxyPassword();

  /**
   * SSL protocols to use for HTTPS requests.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#SSL_PROTOCOLS
   */
  List<String> getSslProtocols();

  /**
   * SSL cipher suites to use for HTTPS requests.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#SSL_CIPHER_SUITES
   */
  List<String> getSslCipherSuites();

  /**
   * Whether to enable SSL hostname verification. Defaults to {@code true}.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#SSL_HOSTNAME_VERIFICATION_ENABLED
   */
  @Value.Default
  default boolean isSslHostnameVerificationEnabled() {
    return true;
  }

  /**
   * Whether to trust all SSL certificates. Defaults to {@code false}.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#SSL_TRUST_ALL
   */
  @Value.Default
  default boolean isSslTrustAll() {
    return false;
  }

  /**
   * Path to the trust store to use for HTTPS requests. Optional, defaults to the system trust
   * store.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#SSL_TRUSTSTORE_PATH
   */
  Optional<Path> getSslTrustStorePath();

  /**
   * Password for the trust store to use for HTTPS requests. Optional, defaults to no password.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#SSL_TRUSTSTORE_PASSWORD
   */
  Optional<String> getSslTrustStorePassword();

  /**
   * Whether to enable compression for HTTP requests. Defaults to {@code true}.
   *
   * <p>This setting is ignored when the {@linkplain #getClientType() HTTP client implementation }
   * is {@code default}.
   *
   * @see OAuth2Properties.Http#COMPRESSION_ENABLED
   */
  @Value.Default
  default boolean isCompressionEnabled() {
    return true;
  }

  /** Merges the given properties into this {@link HttpConfig} and returns the result. */
  default HttpConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    HttpConfig.Builder builder = builder();
    builder.clientTypeOption().set(properties, getClientType());
    builder.readTimeoutOption().set(properties, getReadTimeout());
    builder.connectionTimeoutOption().set(properties, getConnectionTimeout());
    builder.headersOption().set(properties, getHeaders());
    builder.proxyHostOption().set(properties, getProxyHost());
    builder.proxyPortOption().set(properties, getProxyPort().stream().boxed().findAny());
    builder.proxyUsernameOption().set(properties, getProxyUsername());
    builder.proxyPasswordOption().set(properties, getProxyPassword());
    builder.sslProtocolsOption().set(properties, getSslProtocols());
    builder.sslCipherSuitesOption().set(properties, getSslCipherSuites());
    builder
        .sslHostnameVerificationEnabledOption()
        .set(properties, isSslHostnameVerificationEnabled());
    builder.sslTrustAllOption().set(properties, isSslTrustAll());
    builder.sslTrustStorePathOption().set(properties, getSslTrustStorePath());
    builder.sslTrustStorePasswordOption().set(properties, getSslTrustStorePassword());
    builder.compressionEnabledOption().set(properties, isCompressionEnabled());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableHttpConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(HttpConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      clientTypeOption().set(properties);
      readTimeoutOption().set(properties);
      connectionTimeoutOption().set(properties);
      headersOption().set(properties);
      proxyHostOption().set(properties);
      proxyPortOption().set(properties);
      proxyUsernameOption().set(properties);
      proxyPasswordOption().set(properties);
      sslProtocolsOption().set(properties);
      sslCipherSuitesOption().set(properties);
      sslHostnameVerificationEnabledOption().set(properties);
      sslTrustAllOption().set(properties);
      sslTrustStorePathOption().set(properties);
      sslTrustStorePasswordOption().set(properties);
      compressionEnabledOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder clientType(HttpClientType clientType);

    @CanIgnoreReturnValue
    Builder readTimeout(Duration readTimeout);

    @CanIgnoreReturnValue
    Builder connectionTimeout(Duration connectionTimeout);

    @CanIgnoreReturnValue
    Builder headers(Map<String, ? extends String> headers);

    @CanIgnoreReturnValue
    Builder proxyHost(String proxyHost);

    @CanIgnoreReturnValue
    Builder proxyPort(int proxyPort);

    @CanIgnoreReturnValue
    Builder proxyUsername(String proxyUsername);

    @CanIgnoreReturnValue
    Builder proxyPassword(String proxyPassword);

    @CanIgnoreReturnValue
    Builder sslProtocols(Iterable<String> sslProtocols);

    @CanIgnoreReturnValue
    Builder sslCipherSuites(Iterable<String> sslCipherSuites);

    @CanIgnoreReturnValue
    Builder sslHostnameVerificationEnabled(boolean sslHostnameVerificationEnabled);

    @CanIgnoreReturnValue
    Builder sslTrustAll(boolean sslTrustAll);

    @CanIgnoreReturnValue
    Builder sslTrustStorePath(Path sslTrustStorePath);

    @CanIgnoreReturnValue
    Builder sslTrustStorePassword(String sslTrustStorePassword);

    @CanIgnoreReturnValue
    Builder compressionEnabled(boolean compressionEnabled);

    HttpConfig build();

    private ConfigOption<HttpClientType> clientTypeOption() {
      return ConfigOptions.simple(CLIENT_TYPE, this::clientType, HttpClientType::fromString);
    }

    private ConfigOption<Duration> readTimeoutOption() {
      return ConfigOptions.simple(READ_TIMEOUT, this::readTimeout, Duration::parse);
    }

    private ConfigOption<Duration> connectionTimeoutOption() {
      return ConfigOptions.simple(CONNECT_TIMEOUT, this::connectionTimeout, Duration::parse);
    }

    private ConfigOption<Map<String, String>> headersOption() {
      return ConfigOptions.prefixMap(HEADERS_PREFIX, this::headers);
    }

    private ConfigOption<String> proxyHostOption() {
      return ConfigOptions.simple(PROXY_HOST, this::proxyHost);
    }

    private ConfigOption<Integer> proxyPortOption() {
      return ConfigOptions.simple(PROXY_PORT, this::proxyPort, Integer::parseInt);
    }

    private ConfigOption<String> proxyUsernameOption() {
      return ConfigOptions.simple(PROXY_USERNAME, this::proxyUsername);
    }

    private ConfigOption<String> proxyPasswordOption() {
      return ConfigOptions.simple(PROXY_PASSWORD, this::proxyPassword);
    }

    private ConfigOption<List<String>> sslProtocolsOption() {
      return ConfigOptions.simple(
          SSL_PROTOCOLS, this::sslProtocols, ConfigUtils::parseCommaSeparatedList);
    }

    private ConfigOption<List<String>> sslCipherSuitesOption() {
      return ConfigOptions.simple(
          SSL_CIPHER_SUITES, this::sslCipherSuites, ConfigUtils::parseCommaSeparatedList);
    }

    private ConfigOption<Boolean> sslHostnameVerificationEnabledOption() {
      return ConfigOptions.simple(
          SSL_HOSTNAME_VERIFICATION_ENABLED,
          this::sslHostnameVerificationEnabled,
          Boolean::parseBoolean);
    }

    private ConfigOption<Boolean> sslTrustAllOption() {
      return ConfigOptions.simple(SSL_TRUST_ALL, this::sslTrustAll, Boolean::parseBoolean);
    }

    private ConfigOption<Path> sslTrustStorePathOption() {
      return ConfigOptions.simple(SSL_TRUSTSTORE_PATH, this::sslTrustStorePath, Paths::get);
    }

    private ConfigOption<String> sslTrustStorePasswordOption() {
      return ConfigOptions.simple(SSL_TRUSTSTORE_PASSWORD, this::sslTrustStorePassword);
    }

    private ConfigOption<Boolean> compressionEnabledOption() {
      return ConfigOptions.simple(
          COMPRESSION_ENABLED, this::compressionEnabled, Boolean::parseBoolean);
    }
  }
}
