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
import com.dremio.iceberg.authmgr.oauth2.auth.JwtAssertion;
import com.dremio.iceberg.authmgr.oauth2.auth.JwtSigningAlgorithm;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface ClientAssertionConfig extends JwtAssertion {

  ClientAssertionConfig DEFAULT = ImmutableClientAssertionConfig.builder().build();

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getAlgorithm().isPresent()) {
      if (getAlgorithm().get().isRsaAlgorithm()) {
        validator.check(
            getPrivateKey().isPresent(),
            List.of(ALGORITHM, PRIVATE_KEY),
            "client assertion: JWT signing algorithm %s requires a private key",
            getAlgorithm().get().getJwsName());
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
    builder.issuerOption().merge(properties, getIssuer());
    builder.subjectOption().merge(properties, getSubject());
    builder.audienceOption().merge(properties, getAudience());
    builder.tokenLifespanOption().merge(properties, getTokenLifespan());
    builder.extraClaimsOption().merge(properties, getExtraClaims());
    builder.algorithmOption().merge(properties, getAlgorithm());
    builder.privateKeyOption().merge(properties, getPrivateKey());
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
      issuerOption().apply(properties);
      subjectOption().apply(properties);
      audienceOption().apply(properties);
      tokenLifespanOption().apply(properties);
      extraClaimsOption().apply(properties);
      algorithmOption().apply(properties);
      privateKeyOption().apply(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder issuer(String issuer);

    @CanIgnoreReturnValue
    Builder subject(String subject);

    @CanIgnoreReturnValue
    Builder audience(String audience);

    @CanIgnoreReturnValue
    Builder tokenLifespan(Duration tokenLifespan);

    @CanIgnoreReturnValue
    Builder extraClaims(Map<String, ? extends String> extraClaims);

    @CanIgnoreReturnValue
    Builder algorithm(JwtSigningAlgorithm algorithm);

    @CanIgnoreReturnValue
    Builder privateKey(Path privateKey);

    ClientAssertionConfig build();

    default ConfigOption<String> issuerOption() {
      return ConfigOptions.of(ClientAssertion.ISSUER, this::issuer);
    }

    default ConfigOption<String> subjectOption() {
      return ConfigOptions.of(ClientAssertion.SUBJECT, this::subject);
    }

    default ConfigOption<String> audienceOption() {
      return ConfigOptions.of(ClientAssertion.AUDIENCE, this::audience);
    }

    default ConfigOption<Duration> tokenLifespanOption() {
      return ConfigOptions.of(ClientAssertion.TOKEN_LIFESPAN, this::tokenLifespan, Duration::parse);
    }

    default ConfigOption<Map<String, String>> extraClaimsOption() {
      return ConfigOptions.ofPrefix(ClientAssertion.EXTRA_CLAIMS_PREFIX, this::extraClaims);
    }

    default ConfigOption<JwtSigningAlgorithm> algorithmOption() {
      return ConfigOptions.of(
          ClientAssertion.ALGORITHM, this::algorithm, JwtSigningAlgorithm::fromConfigName);
    }

    default ConfigOption<Path> privateKeyOption() {
      return ConfigOptions.of(ClientAssertion.PRIVATE_KEY, this::privateKey, Paths::get);
    }
  }
}
