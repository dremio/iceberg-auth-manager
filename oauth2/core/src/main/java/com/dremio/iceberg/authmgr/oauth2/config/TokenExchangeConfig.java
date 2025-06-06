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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.token.TypedToken.URN_ACCESS_TOKEN;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProvider;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProviders;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.immutables.value.Value;

/**
 * Configuration for OAuth2 token exchange.
 *
 * <p>Note: this configuration is not used for token refreshes when the OAuth2 dialect is {@link
 * com.dremio.iceberg.authmgr.oauth2.config.Dialect#ICEBERG_REST}.
 */
@AuthManagerImmutable
public interface TokenExchangeConfig {

  TokenExchangeConfig DEFAULT = builder().build();

  /**
   * The type of the requested security token. By default, {@link TypedToken#URN_ACCESS_TOKEN}.
   *
   * <p>Currently, it is not possible to request any other token type, so this property is not
   * configurable through system properties.
   */
  @Value.Default
  default URI getRequestedTokenType() {
    return URN_ACCESS_TOKEN;
  }

  /**
   * A URI that indicates the target service or resource where the client intends to use the
   * requested security token.
   *
   * @see OAuth2Properties.TokenExchange#RESOURCE
   */
  Optional<URI> getResource();

  /**
   * The logical name of the target service where the client intends to use the requested security
   * token. This serves a purpose similar to the resource parameter but with the client providing a
   * logical name for the target service.
   *
   * @see OAuth2Properties.TokenExchange#AUDIENCE
   */
  Optional<String> getAudience();

  /**
   * The subject token provider. The provider will be invoked with the current access token; it
   * should return a {@link TypedToken} representing the subject token. It must NOT return null.
   *
   * <p>Note that the current access token may be null if token exchange is used as an initial
   * grant. It is the responsibility of the provider to handle this case. The current access token
   * will never be null, however, if token exchange is used for impersonation.
   *
   * <p>By default, the provider will return the current access token. This should be suitable for
   * most cases.
   *
   * <p>This property cannot be set through configuration, but only programmatically. The
   * configuration exposes two options: the subject token and its type. These options allow to pass
   * a static subject token only.
   *
   * @see OAuth2Properties.TokenExchange#SUBJECT_TOKEN
   * @see OAuth2Properties.TokenExchange#SUBJECT_TOKEN_TYPE
   */
  @Value.Default
  default TokenProvider getSubjectTokenProvider() {
    return TokenProviders.CURRENT_ACCESS_TOKEN;
  }

  /**
   * The actor token provider. The provider will be invoked with the current access token (never
   * null) and the current refresh token, or null if none available; and should return a {@link
   * TypedToken} representing the actor token. If the provider returns null, then no actor token
   * will be used.
   *
   * <p>Note that the current access token may be null if token exchange is used as an initial
   * grant. It is the responsibility of the provider to handle this case. The current access token
   * will never be null, however, if token exchange is used for impersonation.
   *
   * <p>Actor tokens are useful in delegation scenarios. By default, no actor token is used.
   *
   * <p>This property cannot be set through configuration, but only programmatically. The
   * configuration exposes two options: the actor token and its type. These options allow to pass a
   * static actor token only.
   *
   * @see OAuth2Properties.TokenExchange#ACTOR_TOKEN
   * @see OAuth2Properties.TokenExchange#ACTOR_TOKEN_TYPE
   */
  @Value.Default
  default TokenProvider getActorTokenProvider() {
    return TokenProviders.NULL_TOKEN;
  }

  /** Merges the given properties into this {@link TokenExchangeConfig} and returns the result. */
  default TokenExchangeConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    TokenExchangeConfig.Builder builder = builder();
    builder.resourceOption().merge(properties, getResource());
    builder.audienceOption().merge(properties, getAudience());
    builder.subjectTokenProviderOption().merge(properties, getSubjectTokenProvider());
    builder.actorTokenProviderOption().merge(properties, getActorTokenProvider());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableTokenExchangeConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(TokenExchangeConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      resourceOption().apply(properties);
      audienceOption().apply(properties);
      subjectTokenProviderOption().apply(properties);
      actorTokenProviderOption().apply(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder requestedTokenType(URI tokenType);

    @CanIgnoreReturnValue
    Builder resource(URI resource);

    @CanIgnoreReturnValue
    Builder audience(String audience);

    @CanIgnoreReturnValue
    Builder subjectTokenProvider(TokenProvider provider);

    @CanIgnoreReturnValue
    Builder actorTokenProvider(TokenProvider provider);

    @CanIgnoreReturnValue
    default Builder subjectToken(TypedToken token) {
      return subjectTokenProvider(TokenProviders.staticToken(token));
    }

    @CanIgnoreReturnValue
    default Builder actorToken(TypedToken token) {
      return actorTokenProvider(TokenProviders.staticToken(token));
    }

    TokenExchangeConfig build();

    private ConfigOption<URI> resourceOption() {
      return ConfigOptions.of(RESOURCE, this::resource, URI::create);
    }

    private ConfigOption<String> audienceOption() {
      return ConfigOptions.of(AUDIENCE, this::audience);
    }

    private ConfigOption<TokenProvider> subjectTokenProviderOption() {
      return ConfigOptions.ofTokenProvider(
          SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, this::subjectTokenProvider);
    }

    private ConfigOption<TokenProvider> actorTokenProviderOption() {
      return ConfigOptions.ofTokenProvider(ACTOR_TOKEN, ACTOR_TOKEN_TYPE, this::actorTokenProvider);
    }
  }
}
