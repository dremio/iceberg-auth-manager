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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion.ALGORITHM;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion.PRIVATE_KEY;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.immutables.value.Value;

@Value.Immutable
@AuthManagerImmutable
public interface ClientAssertionConfig {

  Duration DEFAULT_TOKEN_LIFESPAN = Duration.ofMinutes(5);

  ClientAssertionConfig DEFAULT = builder().build();

  /**
   * The issuer of the client assertion JWT. Optional. The default is the client ID.
   *
   * @see ClientAssertion#ISSUER
   */
  Optional<Issuer> getIssuer();

  /**
   * The subject of the client assertion JWT. Optional. The default is the client ID.
   *
   * @see ClientAssertion#SUBJECT
   */
  Optional<Subject> getSubject();

  /**
   * The audience of the client assertion JWT. Optional. The default is the token endpoint.
   *
   * @see ClientAssertion#AUDIENCE
   */
  Optional<Audience> getAudience();

  /**
   * The lifespan of the client assertion JWT. Optional. The default is 5 minutes.
   *
   * @see ClientAssertion#TOKEN_LIFESPAN
   */
  @Value.Default
  default Duration getTokenLifespan() {
    return DEFAULT_TOKEN_LIFESPAN;
  }

  /**
   * Extra claims to include in the client assertion JWT. Optional. The default is empty.
   *
   * @see ClientAssertion#EXTRA_CLAIMS_PREFIX
   */
  Map<String, String> getExtraClaims();

  /**
   * The JSON Web Signature (JWS) algorithm to use for the client assertion. Optional. The default
   * is {@link JWSAlgorithm#HS512} if the authentication method is {@link
   * ClientAuthenticationMethod#CLIENT_SECRET_JWT}, or {@link JWSAlgorithm#RS512} if the
   * authentication method is {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT}.
   *
   * <p>Algorithm names must match the "alg" Param Value as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section 3.1</a>.
   *
   * @see ClientAssertion#ALGORITHM
   */
  Optional<JWSAlgorithm> getAlgorithm();

  /**
   * The path on the local filesystem to the private key to use for signing the client assertion
   * JWT. Required if the authentication method is "private_key_jwt". The file must be in PEM
   * format; it may contain a private key, or a private key and a certificate chain. Only the
   * private key is used.
   *
   * @see ClientAssertion#PRIVATE_KEY
   */
  Optional<Path> getPrivateKey();

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getAlgorithm().isPresent()) {
      if (JWSAlgorithm.Family.SIGNATURE.contains(getAlgorithm().get())) {
        validator.check(
            getPrivateKey().isPresent(),
            List.of(ALGORITHM, PRIVATE_KEY),
            "client assertion: JWS signing algorithm %s requires a private key",
            getAlgorithm().get().getName());
      } else {
        validator.check(
            getPrivateKey().isEmpty(),
            List.of(ALGORITHM, PRIVATE_KEY),
            "client assertion: private key must not be set for JWS algorithm %s",
            getAlgorithm().get().getName());
      }
    }
    if (getPrivateKey().isPresent()) {
      validator.check(
          Files.isReadable(getPrivateKey().get()),
          PRIVATE_KEY,
          "client assertion: private key path '%s' is not a file or is not readable",
          getPrivateKey().get());
    }
    validator.validate();
  }

  /** Merges the given properties into this {@link ClientAssertionConfig} and returns the result. */
  default ClientAssertionConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    ClientAssertionConfig.Builder builder = builder();
    builder.issuerOption().set(properties, getIssuer());
    builder.subjectOption().set(properties, getSubject());
    builder.audienceOption().set(properties, getAudience());
    builder.tokenLifespanOption().set(properties, getTokenLifespan());
    builder.extraClaimsOption().set(properties, getExtraClaims());
    builder.algorithmOption().set(properties, getAlgorithm());
    builder.privateKeyOption().set(properties, getPrivateKey());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableClientAssertionConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(ClientAssertionConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      issuerOption().set(properties);
      subjectOption().set(properties);
      audienceOption().set(properties);
      tokenLifespanOption().set(properties);
      extraClaimsOption().set(properties);
      algorithmOption().set(properties);
      privateKeyOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder issuer(Issuer issuer);

    @CanIgnoreReturnValue
    Builder subject(Subject subject);

    @CanIgnoreReturnValue
    Builder audience(Audience audience);

    @CanIgnoreReturnValue
    Builder tokenLifespan(Duration tokenLifespan);

    @CanIgnoreReturnValue
    Builder extraClaims(Map<String, ? extends String> extraClaims);

    @CanIgnoreReturnValue
    Builder algorithm(JWSAlgorithm algorithm);

    @CanIgnoreReturnValue
    Builder privateKey(Path privateKey);

    ClientAssertionConfig build();

    default ConfigOption<Issuer> issuerOption() {
      return ConfigOptions.simple(ClientAssertion.ISSUER, this::issuer, Issuer::parse);
    }

    default ConfigOption<Subject> subjectOption() {
      return ConfigOptions.simple(ClientAssertion.SUBJECT, this::subject, Subject::new);
    }

    default ConfigOption<Audience> audienceOption() {
      return ConfigOptions.simple(ClientAssertion.AUDIENCE, this::audience, Audience::new);
    }

    default ConfigOption<Duration> tokenLifespanOption() {
      return ConfigOptions.simple(
          ClientAssertion.TOKEN_LIFESPAN, this::tokenLifespan, Duration::parse);
    }

    default ConfigOption<Map<String, String>> extraClaimsOption() {
      return ConfigOptions.prefixMap(ClientAssertion.EXTRA_CLAIMS_PREFIX, this::extraClaims);
    }

    default ConfigOption<JWSAlgorithm> algorithmOption() {
      return ConfigOptions.simple(ClientAssertion.ALGORITHM, this::algorithm, JWSAlgorithm::parse);
    }

    default ConfigOption<Path> privateKeyOption() {
      return ConfigOptions.simple(ClientAssertion.PRIVATE_KEY, this::privateKey, Paths::get);
    }
  }
}
