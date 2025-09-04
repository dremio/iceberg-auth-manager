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
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration properties for the <a href="https://datatracker.ietf.org/doc/html/rfc8693">Token
 * Exchange</a> flow.
 *
 * <p>This flow allows a client to exchange one token for another, typically to obtain a token that
 * is more suitable for the target resource or service.
 *
 * <p>See the <a href="./token-exchange.md">Token Exchange</a> section for more details.
 */
public interface TokenExchangeConfig {

  String GROUP_NAME = "token-exchange";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String SUBJECT_TOKEN = "subject-token";
  String SUBJECT_TOKEN_TYPE = "subject-token-type";
  String ACTOR_TOKEN = "actor-token";
  String ACTOR_TOKEN_TYPE = "actor-token-type";
  String REQUESTED_TOKEN_TYPE = "requested-token-type";
  String RESOURCE = "resource";
  String AUDIENCE = "audience";

  String DEFAULT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

  /**
   * The subject token to exchange.
   *
   * <p>If this value is present, the subject token will be used as-is. If this value is not
   * present, the subject token will be dynamically fetched using the configuration provided under
   * the {@value #SUBJECT_TOKEN} prefix.
   */
  @WithName(SUBJECT_TOKEN)
  Optional<TypelessAccessToken> getSubjectToken();

  /**
   * The type of the subject token. Must be a valid URN. The default is {@code
   * urn:ietf:params:oauth:token-type:access_token}.
   *
   * <p>If the agent is configured to dynamically fetch the subject token, this property is ignored
   * since only access tokens can be dynamically fetched.
   *
   * @see TokenExchangeConfig#SUBJECT_TOKEN_TYPE
   */
  @WithName(SUBJECT_TOKEN_TYPE)
  @WithDefault(DEFAULT_TOKEN_TYPE)
  TokenTypeURI getSubjectTokenType();

  /**
   * The actor token to exchange.
   *
   * <p>If this value is present, the actor token will be used as-is. If this value is not present,
   * the actor token will be dynamically fetched using the configuration provided under the {@value
   * #ACTOR_TOKEN} prefix. If no configuration is provided, no actor token will be used.
   */
  @WithName(ACTOR_TOKEN)
  Optional<TypelessAccessToken> getActorToken();

  /**
   * The type of the actor token. Must be a valid URN. The default is {@code
   * urn:ietf:params:oauth:token-type:access_token}.
   *
   * <p>If the agent is configured to dynamically fetch the actor token, this property is ignored
   * since only access tokens can be dynamically fetched.
   *
   * @see TokenExchangeConfig#ACTOR_TOKEN_TYPE
   */
  @WithName(ACTOR_TOKEN_TYPE)
  @WithDefault(DEFAULT_TOKEN_TYPE)
  TokenTypeURI getActorTokenType();

  /**
   * The type of the requested security token. Must be a valid URN. The default is {@code
   * urn:ietf:params:oauth:token-type:access_token}.
   */
  @WithName(REQUESTED_TOKEN_TYPE)
  @WithDefault(DEFAULT_TOKEN_TYPE)
  TokenTypeURI getRequestedTokenType();

  /**
   * The configuration to use for fetching the subject token. Required if {@value #SUBJECT_TOKEN} is
   * not set.
   *
   * <p>This is a prefix property; any property that can be set under the {@value
   * OAuth2Config#PREFIX} prefix can also be set under this prefix.
   *
   * <p>The effective subject token fetch configuration will be the result of merging the
   * subject-specific configuration with the main configuration.
   *
   * <p>Example:
   *
   * <pre>{@code
   * rest.auth.oauth2.grant-type=token_exchange
   * rest.auth.oauth2.token-endpoint=https://main-token-endpoint.com/token
   * rest.auth.oauth2.client-id=main-client-id
   * rest.auth.oauth2.client-secret=main-client-secret
   * rest.auth.oauth2.token-exchange.subject-token.grant-type=client_credentials
   * rest.auth.oauth2.token-exchange.subject-token.client-id=subject-client-id
   * rest.auth.oauth2.token-exchange.subject-token.client-secret=subject-client-secret
   * }</pre>
   *
   * The above configuration will result in a token exchange where the subject token is obtained
   * using the client credentials grant type, with specific client ID and secret, but sharing the
   * token endpoint, client authentication method and other settings with the main agent.
   */
  @WithName(SUBJECT_TOKEN)
  Map<String, String> getSubjectTokenConfig();

  /**
   * The configuration to use for fetching the actor token. Optional; required only if {@value
   * #ACTOR_TOKEN} is not set but an actor token is required.
   *
   * <p>This is a prefix property; any property that can be set under the {@value
   * OAuth2Config#PREFIX} prefix can also be set under this prefix.
   *
   * <p>The effective actor token fetch configuration will be the result of merging the
   * actor-specific configuration with the main configuration.
   *
   * <p>Example:
   *
   * <pre>{@code
   * rest.auth.oauth2.grant-type=token_exchange
   * rest.auth.oauth2.token-endpoint=https://main-token-endpoint.com/token
   * rest.auth.oauth2.client-id=main-client-id
   * rest.auth.oauth2.client-secret=main-client-secret
   * rest.auth.oauth2.token-exchange.actor-token.grant-type=client_credentials
   * rest.auth.oauth2.token-exchange.actor-token.client-id=actor-client-id
   * rest.auth.oauth2.token-exchange.actor-token.client-secret=actor-client-secret
   * }</pre>
   *
   * The above configuration will result in a token exchange where the actor token is obtained using
   * the client credentials grant type, with specific client ID and secret, but sharing the token
   * endpoint, client authentication method and other settings with the main agent.
   */
  @WithName(ACTOR_TOKEN)
  Map<String, String> getActorTokenConfig();

  /**
   * A URI that indicates the target service or resource where the client intends to use the
   * requested security token. Optional.
   */
  @WithName(RESOURCE)
  Optional<URI> getResource();

  /**
   * The logical name of the target service where the client intends to use the requested security
   * token. This serves a purpose similar to the resource parameter but with the client providing a
   * logical name for the target service. Optional.
   */
  @WithName(AUDIENCE)
  Optional<Audience> getAudience();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getSubjectToken().isEmpty()) {
      validator.check(
          getSubjectTokenType().equals(TokenTypeURI.ACCESS_TOKEN),
          PREFIX + '.' + SUBJECT_TOKEN_TYPE,
          "subject token type must be %s when using dynamic subject token",
          TokenTypeURI.ACCESS_TOKEN);
    }
    if (getActorToken().isEmpty()) {
      validator.check(
          getActorTokenType().equals(TokenTypeURI.ACCESS_TOKEN),
          PREFIX + '.' + ACTOR_TOKEN_TYPE,
          "actor token type must be %s when using dynamic actor token",
          TokenTypeURI.ACCESS_TOKEN);
    }
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getSubjectToken().ifPresent(t -> properties.put(PREFIX + '.' + SUBJECT_TOKEN, t.getValue()));
    getActorToken().ifPresent(t -> properties.put(PREFIX + '.' + ACTOR_TOKEN, t.getValue()));
    properties.put(PREFIX + '.' + SUBJECT_TOKEN_TYPE, getSubjectTokenType().getURI().toString());
    properties.put(PREFIX + '.' + ACTOR_TOKEN_TYPE, getActorTokenType().getURI().toString());
    properties.put(
        PREFIX + '.' + REQUESTED_TOKEN_TYPE, getRequestedTokenType().getURI().toString());
    getResource().ifPresent(r -> properties.put(PREFIX + '.' + RESOURCE, r.toString()));
    getAudience().ifPresent(a -> properties.put(PREFIX + '.' + AUDIENCE, a.getValue()));
    getSubjectTokenConfig()
        .forEach((k, v) -> properties.put(PREFIX + '.' + SUBJECT_TOKEN + '.' + k, v));
    getActorTokenConfig()
        .forEach((k, v) -> properties.put(PREFIX + '.' + ACTOR_TOKEN + '.' + k, v));
    return Map.copyOf(properties);
  }
}
