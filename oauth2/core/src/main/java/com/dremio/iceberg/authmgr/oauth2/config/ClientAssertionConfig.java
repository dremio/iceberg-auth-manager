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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Configuration properties for JWT client assertion as specified in <a
 * href="https://datatracker.ietf.org/doc/html/rfc7523">JSON Web Token (JWT) Profile for OAuth 2.0
 * Client Authentication and Authorization Grants</a>.
 *
 * <p>These properties allow the client to authenticate using the {@code client_secret_jwt} or
 * {@code private_key_jwt} authentication methods.
 */
public interface ClientAssertionConfig {

  String GROUP_NAME = "client-assertion.jwt";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ISSUER = "issuer";
  String SUBJECT = "subject";
  String AUDIENCE = "audience";
  String TOKEN_LIFESPAN = "token-lifespan";
  String ALGORITHM = "algorithm";
  String PRIVATE_KEY = "private-key";
  String EXTRA_CLAIMS = "extra-claims";

  String DEFAULT_TOKEN_LIFESPAN = "PT5M";

  /** The issuer of the client assertion JWT. Optional. The default is the client ID. */
  @WithName(ISSUER)
  Optional<Issuer> getIssuer();

  /** The subject of the client assertion JWT. Optional. The default is the client ID. */
  @WithName(SUBJECT)
  Optional<Subject> getSubject();

  /** The audience of the client assertion JWT. Optional. The default is the token endpoint. */
  @WithName(AUDIENCE)
  Optional<Audience> getAudience();

  /** The expiration time of the client assertion JWT. Optional. The default is 5 minutes. */
  @WithName(TOKEN_LIFESPAN)
  @WithDefault(DEFAULT_TOKEN_LIFESPAN)
  Duration getTokenLifespan();

  /**
   * The signing algorithm to use for the client assertion JWT. Optional. The default is {@link
   * JWSAlgorithm#HS512} if the authentication method is {@link
   * ClientAuthenticationMethod#CLIENT_SECRET_JWT}, or {@link JWSAlgorithm#RS512} if the
   * authentication method is {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT}.
   *
   * <p>Algorithm names must match the "alg" Param Value as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section 3.1</a>.
   */
  @WithName(ALGORITHM)
  Optional<JWSAlgorithm> getAlgorithm();

  /**
   * The path on the local filesystem to the private key to use for signing the client assertion
   * JWT. Required if the authentication method is {@link
   * ClientAuthenticationMethod#PRIVATE_KEY_JWT}. The file must be in PEM format; it may contain a
   * private key, or a private key and a certificate chain. Only the private key is used.
   */
  @WithName(PRIVATE_KEY)
  Optional<Path> getPrivateKey();

  /**
   * Extra claims to include in the client assertion JWT. This is a prefix property, and multiple
   * values can be set, each with a different key and value.
   */
  @WithName(EXTRA_CLAIMS)
  Map<String, String> getExtraClaims();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getAlgorithm().isPresent()) {
      if (JWSAlgorithm.Family.SIGNATURE.contains(getAlgorithm().get())) {
        validator.check(
            getPrivateKey().isPresent(),
            List.of(PREFIX + '.' + ALGORITHM, PREFIX + '.' + PRIVATE_KEY),
            "client assertion: JWS signing algorithm '%s' requires a private key",
            getAlgorithm().get().getName());
      } else if (JWSAlgorithm.Family.HMAC_SHA.contains(getAlgorithm().get())) {
        validator.check(
            getPrivateKey().isEmpty(),
            List.of(PREFIX + '.' + ALGORITHM, PREFIX + '.' + PRIVATE_KEY),
            "client assertion: private key must not be set for JWS algorithm '%s'",
            getAlgorithm().get().getName());
      } else {
        validator.check(
            false,
            PREFIX + '.' + ALGORITHM,
            "client assertion: unsupported JWS algorithm '%s', must be one of: %s",
            getAlgorithm().get().getName(),
            Stream.concat(
                    JWSAlgorithm.Family.HMAC_SHA.stream(), JWSAlgorithm.Family.SIGNATURE.stream())
                .map(JWSAlgorithm::getName)
                .collect(Collectors.joining("', '", "'", "'")));
      }
    }
    if (getPrivateKey().isPresent()) {
      validator.check(
          Files.isReadable(getPrivateKey().get()),
          PREFIX + '.' + PRIVATE_KEY,
          "client assertion: private key path '%s' is not a file or is not readable",
          getPrivateKey().get());
    }
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getIssuer().ifPresent(i -> properties.put(PREFIX + '.' + ISSUER, i.getValue()));
    getSubject().ifPresent(s -> properties.put(PREFIX + '.' + SUBJECT, s.getValue()));
    getAudience().ifPresent(a -> properties.put(PREFIX + '.' + AUDIENCE, a.getValue()));
    properties.put(PREFIX + '.' + TOKEN_LIFESPAN, getTokenLifespan().toString());
    getAlgorithm().ifPresent(a -> properties.put(PREFIX + '.' + ALGORITHM, a.getName()));
    getPrivateKey().ifPresent(p -> properties.put(PREFIX + '.' + PRIVATE_KEY, p.toString()));
    getExtraClaims().forEach((k, v) -> properties.put(PREFIX + '.' + EXTRA_CLAIMS + '.' + k, v));
    return Map.copyOf(properties);
  }
}
