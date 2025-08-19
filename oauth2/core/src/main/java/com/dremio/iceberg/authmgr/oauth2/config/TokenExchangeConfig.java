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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_CONFIG_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.ACTOR_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.REQUESTED_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_CONFIG_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.SUBJECT_TOKEN_TYPE;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.immutables.value.Value;

/** Configuration for OAuth2 token exchange. */
@AuthManagerImmutable
public interface TokenExchangeConfig {

  TokenExchangeConfig DEFAULT = builder().build();

  /**
   * The subject token to exchange.
   *
   * <p>If this value is present, the subject token will be used as-is. If this value is not
   * present, the subject token will be dynamically fetched using the configuration provided under
   * {@link #getSubjectTokenConfig()}.
   *
   * @see OAuth2Properties.TokenExchange#SUBJECT_TOKEN
   */
  Optional<Token> getSubjectToken();

  /**
   * The type of the subject token. Must be a valid URN. The default is {@link
   * TokenTypeURI#ACCESS_TOKEN}.
   *
   * <p>If the agent is configured to dynamically fetch the subject token, this property is ignored
   * since only access tokens can be dynamically fetched.
   *
   * @see OAuth2Properties.TokenExchange#SUBJECT_TOKEN_TYPE
   */
  @Value.Default
  default TokenTypeURI getSubjectTokenType() {
    return TokenTypeURI.ACCESS_TOKEN;
  }

  /**
   * The actor token to exchange.
   *
   * <p>If this value is present, the actor token will be used as-is. If this value is not present,
   * the actor token will be dynamically fetched using the configuration provided under {@link
   * #getActorTokenConfig()}. If no configuration is provided, no actor token will be used.
   *
   * @see OAuth2Properties.TokenExchange#ACTOR_TOKEN
   */
  Optional<Token> getActorToken();

  /**
   * The type of the actor token. Must be a valid URN. The default is {@link
   * TokenTypeURI#ACCESS_TOKEN}.
   *
   * <p>If the agent is configured to dynamically fetch the actor token, this property is ignored
   * since only access tokens can be dynamically fetched.
   *
   * @see OAuth2Properties.TokenExchange#ACTOR_TOKEN_TYPE
   */
  @Value.Default
  default TokenTypeURI getActorTokenType() {
    return TokenTypeURI.ACCESS_TOKEN;
  }

  /**
   * The type of the requested security token. The default is {@code
   * urn:ietf:params:oauth:token-type:access_token}.
   *
   * @see OAuth2Properties.TokenExchange#REQUESTED_TOKEN_TYPE
   */
  @Value.Default
  default TokenTypeURI getRequestedTokenType() {
    return TokenTypeURI.ACCESS_TOKEN;
  }

  /**
   * A URI that indicates the target service or resource where the client intends to use the
   * requested security token.
   *
   * @see OAuth2Properties.TokenExchange#RESOURCE
   */
  List<URI> getResources();

  /**
   * The logical names of the target service where the client intends to use the requested security
   * token. This serves a purpose similar to the resource parameter but with the client providing a
   * logical name for the target service.
   *
   * @see OAuth2Properties.TokenExchange#AUDIENCE
   */
  List<Audience> getAudiences();

  /**
   * The configuration to use for fetching the subject token. Required if {@link #getSubjectToken()}
   * is not set.
   *
   * <p>Note: validation of this configuration is done lazily, when the token is actually fetched.
   */
  Map<String, String> getSubjectTokenConfig();

  /**
   * The configuration to use for fetching the actor token. Required if {@link #getActorToken()} is
   * not set but an actor token is required.
   *
   * <p>Note: validation of this configuration is done lazily, when the token is actually fetched.
   */
  Map<String, String> getActorTokenConfig();

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getSubjectToken().isEmpty()) {
      validator.check(
          getSubjectTokenType().equals(TokenTypeURI.ACCESS_TOKEN),
          SUBJECT_TOKEN_TYPE,
          "subject token type must be %s when using dynamic subject token",
          TokenTypeURI.ACCESS_TOKEN);
    }
    if (getActorToken().isEmpty()) {
      validator.check(
          getActorTokenType().equals(TokenTypeURI.ACCESS_TOKEN),
          ACTOR_TOKEN_TYPE,
          "actor token type must be %s when using dynamic actor token",
          TokenTypeURI.ACCESS_TOKEN);
    }
    validator.validate();
  }

  /** Merges the given properties into this {@link TokenExchangeConfig} and returns the result. */
  default TokenExchangeConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    TokenExchangeConfig.Builder builder = builder();
    builder.resourcesOption().set(properties, getResources());
    builder.audiencesOption().set(properties, getAudiences());
    builder.subjectTokenOption().set(properties, getSubjectToken());
    builder.actorTokenOption().set(properties, getActorToken());
    builder.subjectTokenTypeOption().set(properties, getSubjectTokenType());
    builder.actorTokenTypeOption().set(properties, getActorTokenType());
    builder.subjectTokenConfigOption().set(properties, getSubjectTokenConfig());
    builder.actorTokenConfigOption().set(properties, getActorTokenConfig());
    builder.requestedTokenTypeOption().set(properties, getRequestedTokenType());
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
      resourcesOption().set(properties);
      audiencesOption().set(properties);
      subjectTokenOption().set(properties);
      actorTokenOption().set(properties);
      subjectTokenTypeOption().set(properties);
      actorTokenTypeOption().set(properties);
      subjectTokenConfigOption().set(properties);
      actorTokenConfigOption().set(properties);
      requestedTokenTypeOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder requestedTokenType(TokenTypeURI tokenType);

    @CanIgnoreReturnValue
    Builder resources(Iterable<? extends URI> resources);

    @CanIgnoreReturnValue
    Builder audiences(Iterable<? extends Audience> audiences);

    @CanIgnoreReturnValue
    Builder subjectToken(Token token);

    @CanIgnoreReturnValue
    Builder actorToken(Token token);

    @CanIgnoreReturnValue
    Builder subjectTokenType(TokenTypeURI tokenType);

    @CanIgnoreReturnValue
    Builder actorTokenType(TokenTypeURI tokenType);

    @CanIgnoreReturnValue
    Builder subjectTokenConfig(Map<String, ? extends String> config);

    @CanIgnoreReturnValue
    Builder actorTokenConfig(Map<String, ? extends String> config);

    TokenExchangeConfig build();

    private ConfigOption<List<URI>> resourcesOption() {
      return ConfigOptions.simple(RESOURCE, this::resources, ConfigUtils::parseUriList);
    }

    private ConfigOption<List<Audience>> audiencesOption() {
      return ConfigOptions.simple(AUDIENCE, this::audiences, ConfigUtils::parseAudienceList);
    }

    private ConfigOption<Token> subjectTokenOption() {
      return ConfigOptions.simple(SUBJECT_TOKEN, this::subjectToken, TypelessAccessToken::new);
    }

    private ConfigOption<Token> actorTokenOption() {
      return ConfigOptions.simple(ACTOR_TOKEN, this::actorToken, TypelessAccessToken::new);
    }

    private ConfigOption<TokenTypeURI> subjectTokenTypeOption() {
      return ConfigOptions.simple(
          SUBJECT_TOKEN_TYPE, this::subjectTokenType, ConfigUtils::parseTokenTypeURI);
    }

    private ConfigOption<TokenTypeURI> actorTokenTypeOption() {
      return ConfigOptions.simple(
          ACTOR_TOKEN_TYPE, this::actorTokenType, ConfigUtils::parseTokenTypeURI);
    }

    private ConfigOption<Map<String, String>> subjectTokenConfigOption() {
      return ConfigOptions.prefixMap(
          SUBJECT_CONFIG_PREFIX, OAuth2Properties.PREFIX, this::subjectTokenConfig);
    }

    private ConfigOption<Map<String, String>> actorTokenConfigOption() {
      return ConfigOptions.prefixMap(
          ACTOR_CONFIG_PREFIX, OAuth2Properties.PREFIX, this::actorTokenConfig);
    }

    private ConfigOption<TokenTypeURI> requestedTokenTypeOption() {
      return ConfigOptions.simple(
          REQUESTED_TOKEN_TYPE, this::requestedTokenType, ConfigUtils::parseTokenTypeURI);
    }
  }
}
