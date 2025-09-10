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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClient;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.google.errorprone.annotations.MustBeClosed;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

/** Configuration properties for HTTP clients. */
public interface HttpConfig {

  String GROUP_NAME = "http";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String CLIENT_TYPE = "client-type";
  String READ_TIMEOUT = "read-timeout";
  String CONNECT_TIMEOUT = "connect-timeout";
  String HEADERS = "headers";
  String COMPRESSION_ENABLED = "compression.enabled";
  String SSL_PROTOCOLS = "ssl.protocols";
  String SSL_CIPHER_SUITES = "ssl.cipher-suites";
  String SSL_HOSTNAME_VERIFICATION_ENABLED = "ssl.hostname-verification.enabled";
  String SSL_TRUST_ALL = "ssl.trust-all";
  String SSL_TRUSTSTORE_PATH = "ssl.trust-store.path";
  String SSL_TRUSTSTORE_PASSWORD = "ssl.trust-store.password";
  String PROXY_HOST = "proxy.host";
  String PROXY_PORT = "proxy.port";
  String PROXY_USERNAME = "proxy.username";
  String PROXY_PASSWORD = "proxy.password";

  String DEFAULT_READ_TIMEOUT = "PT30S";
  String DEFAULT_CONNECT_TIMEOUT = "PT10S";

  /** Creates an HTTP client based on this configuration. */
  @MustBeClosed
  default HttpClient newHttpClient() {
    return getClientType().newHttpClient(this);
  }

  /**
   * The type of HTTP client to use for making HTTP requests to the OAuth2 server. Valid values are:
   *
   * <ul>
   *   <li>{@link HttpClientType#DEFAULT}: uses the built-in URLConnection-based client provided by
   *       the underlying OAuth2 library.
   *   <li>{@link HttpClientType#APACHE}: uses the Apache HttpClient library, provided by Iceberg's
   *       runtime.
   * </ul>
   *
   * <p>Optional, defaults to {@code default}.
   */
  @WithName(CLIENT_TYPE)
  @WithDefault("DEFAULT")
  HttpClientType getClientType();

  /**
   * The read timeout for HTTP requests. Optional, defaults to {@value #DEFAULT_READ_TIMEOUT}. Must
   * be a valid <a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(READ_TIMEOUT)
  @WithDefault(DEFAULT_READ_TIMEOUT)
  Duration getReadTimeout();

  /**
   * The connection timeout for HTTP requests. Optional, defaults to {@value
   * #DEFAULT_CONNECT_TIMEOUT}. Must be a valid <a
   * href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(CONNECT_TIMEOUT)
  @WithDefault(DEFAULT_CONNECT_TIMEOUT)
  Duration getConnectionTimeout();

  /**
   * HTTP headers to include in each HTTP request. This is a prefix property, and multiple values
   * can be set, each with a different key and value.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(HEADERS)
  Map<String, String> getHeaders();

  /**
   * Whether to enable compression for HTTP requests. Optional, defaults to {@code true}.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(COMPRESSION_ENABLED)
  @WithDefault("true")
  boolean isCompressionEnabled();

  /**
   * A comma-separated list of SSL protocols to use for HTTPS requests. Optional, defaults to the
   * system protocols.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(SSL_PROTOCOLS)
  Optional<String> getSslProtocols();

  /**
   * A comma-separated list of SSL cipher suites to use for HTTPS requests. Optional, defaults to
   * the system cipher suites.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(SSL_CIPHER_SUITES)
  Optional<String> getSslCipherSuites();

  /**
   * Whether to enable SSL hostname verification for HTTPS requests.
   *
   * <p>WARNING: Disabling hostname verification is a security risk and should only be used for
   * testing purposes.
   *
   * <p>Optional, defaults to {@code true}.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(SSL_HOSTNAME_VERIFICATION_ENABLED)
  @WithDefault("true")
  boolean isSslHostnameVerificationEnabled();

  /**
   * Whether to trust all SSL certificates for HTTPS requests.
   *
   * <p>WARNING: Trusting all SSL certificates is a security risk and should only be used for
   * testing purposes.
   *
   * <p>Optional, defaults to {@code false}.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(SSL_TRUST_ALL)
  @WithDefault("false")
  boolean isSslTrustAll();

  /**
   * Path to the trust store to use for HTTPS requests. Optional, defaults to the system trust
   * store.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(SSL_TRUSTSTORE_PATH)
  Optional<Path> getSslTrustStorePath();

  /**
   * Password for the trust store to use for HTTPS requests. Optional, defaults to no password.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}, or if {@link #SSL_TRUSTSTORE_PATH} is not set.
   */
  @WithName(SSL_TRUSTSTORE_PASSWORD)
  Optional<String> getSslTrustStorePassword();

  /**
   * Proxy host to use for HTTP requests. Optional, defaults to no proxy. If set, the proxy port
   * must also be set.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(PROXY_HOST)
  Optional<String> getProxyHost();

  /**
   * Proxy port to use for HTTP requests. Optional, defaults to no proxy. If set, the proxy host
   * must also be set.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(PROXY_PORT)
  OptionalInt getProxyPort();

  /**
   * Proxy username to use for HTTP requests. Optional, defaults to no authentication. If set, the
   * proxy password must also be set.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(PROXY_USERNAME)
  Optional<String> getProxyUsername();

  /**
   * Proxy password to use for HTTP requests. Optional, defaults to no authentication. If set, the
   * proxy username must also be set.
   *
   * <p>This setting is ignored when the {@linkplain #CLIENT_TYPE client type} is set to {@code
   * default}.
   */
  @WithName(PROXY_PASSWORD)
  Optional<String> getProxyPassword();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getSslTrustStorePath().isPresent()) {
      validator.check(
          Files.isReadable(getSslTrustStorePath().get()),
          PREFIX + '.' + SSL_TRUSTSTORE_PATH,
          "http: SSL truststore path '%s' is not a file or is not readable",
          getSslTrustStorePath().get());
    }
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    properties.put(PREFIX + '.' + CLIENT_TYPE, getClientType().name());
    properties.put(PREFIX + '.' + READ_TIMEOUT, getReadTimeout().toString());
    properties.put(PREFIX + '.' + CONNECT_TIMEOUT, getConnectionTimeout().toString());
    getHeaders().forEach((k, v) -> properties.put(PREFIX + '.' + HEADERS + '.' + k, v));
    getProxyHost().ifPresent(h -> properties.put(PREFIX + '.' + PROXY_HOST, h));
    getProxyPort().ifPresent(p -> properties.put(PREFIX + '.' + PROXY_PORT, String.valueOf(p)));
    getProxyUsername().ifPresent(u -> properties.put(PREFIX + '.' + PROXY_USERNAME, u));
    getProxyPassword().ifPresent(p -> properties.put(PREFIX + '.' + PROXY_PASSWORD, p));
    getSslProtocols().ifPresent(p -> properties.put(PREFIX + '.' + SSL_PROTOCOLS, p));
    getSslCipherSuites().ifPresent(c -> properties.put(PREFIX + '.' + SSL_CIPHER_SUITES, c));
    properties.put(
        PREFIX + '.' + SSL_HOSTNAME_VERIFICATION_ENABLED,
        String.valueOf(isSslHostnameVerificationEnabled()));
    properties.put(PREFIX + '.' + SSL_TRUST_ALL, String.valueOf(isSslTrustAll()));
    getSslTrustStorePath()
        .ifPresent(p -> properties.put(PREFIX + '.' + SSL_TRUSTSTORE_PATH, p.toString()));
    getSslTrustStorePassword()
        .ifPresent(p -> properties.put(PREFIX + '.' + SSL_TRUSTSTORE_PASSWORD, p));
    properties.put(PREFIX + '.' + COMPRESSION_ENABLED, String.valueOf(isCompressionEnabled()));
    return Map.copyOf(properties);
  }
}
