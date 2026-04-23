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
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Configuration properties for <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449:
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>.
 *
 * <p>When enabled, the agent generates or loads an asymmetric keypair and attaches a signed DPoP
 * proof JWT to every request sent to the authorization server's token endpoint, as well as to every
 * authenticated request sent to the protected resource server.
 *
 * <p>DPoP is disabled by default. To enable it, set {@code rest.auth.oauth2.dpop.enabled=true}.
 */
public interface DpopConfig {

  String GROUP_NAME = "dpop";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ENABLED = "enabled";
  String ALGORITHM = "algorithm";
  String PRIVATE_KEY = "private-key";
  String PUBLIC_KEY = "public-key";

  String DEFAULT_ALGORITHM = "ES256";

  /**
   * Whether DPoP support is enabled. Defaults to {@code false}.
   *
   * <p>When enabled, every request to the token endpoint and every authenticated request to the
   * resource server will carry a {@code DPoP} header with a signed proof JWT, and the {@code
   * Authorization} header scheme for resource-server requests will switch from {@code Bearer} to
   * {@code DPoP}.
   */
  @WithName(ENABLED)
  @WithDefault("false")
  boolean isEnabled();

  /**
   * The JWS algorithm to use for signing DPoP proof JWTs. Defaults to {@value #DEFAULT_ALGORITHM}.
   *
   * <p>Per RFC 9449, the signing key MUST be asymmetric; thus only asymmetric algorithms are
   * accepted (e.g. {@code ES256}, {@code ES384}, {@code ES512}, {@code RS256}, {@code PS256},
   * etc.). {@code ES256K} and the {@code EdDSA} family are not currently supported.
   *
   * <p>Algorithm names must match the "alg" Param Value as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section 3.1</a>.
   */
  @WithName(ALGORITHM)
  @WithDefault(DEFAULT_ALGORITHM)
  JWSAlgorithm getAlgorithm();

  /**
   * The path on the local filesystem to the private key to use for signing DPoP proofs. Optional.
   *
   * <p>If not set, a fresh ephemeral keypair matching the configured {@value #ALGORITHM} is
   * generated when the agent starts and discarded on shutdown.
   *
   * <p>If set, the file must be in PEM format; it may contain a private key, or a private key and a
   * certificate chain. Only the private key is used.
   *
   * <p>Supported key formats are:
   *
   * <ul>
   *   <li>RSA & ECDSA in PKCS#8 format ({@code BEGIN PRIVATE KEY}): always supported
   *   <li>RSA in PKCS#1 format ({@code BEGIN RSA PRIVATE KEY}): requires the BouncyCastle library
   *   <li>ECDSA in EC SEC 1 format ({@code BEGIN EC PRIVATE KEY}): requires the BouncyCastle
   *       library
   * </ul>
   *
   * Only unencrypted keys are supported currently.
   */
  @WithName(PRIVATE_KEY)
  Optional<Path> getPrivateKey();

  /**
   * The path on the local filesystem to an optional public key PEM file accompanying {@value
   * #PRIVATE_KEY}. Optional.
   *
   * <p>When set, the file must contain a {@code -----BEGIN PUBLIC KEY-----} block (X.509
   * SubjectPublicKeyInfo, as produced by {@code openssl pkey -pubout}) for the public counterpart
   * of the configured private key. When not set, the public key is derived from the private key
   * automatically; this always works for RSA keys but requires BouncyCastle on the runtime
   * classpath for EC keys.
   *
   * <p>Ignored when {@value #PRIVATE_KEY} is not set (ephemeral mode).
   */
  @WithName(PUBLIC_KEY)
  Optional<Path> getPublicKey();

  default void validate() {
    if (!isEnabled()) {
      return;
    }
    ConfigValidator validator = new ConfigValidator();
    JWSAlgorithm algorithm = getAlgorithm();
    validator.check(
        ConfigUtils.SUPPORTED_DPOP_RSA_ALGORITHMS.contains(algorithm)
            || ConfigUtils.SUPPORTED_DPOP_EC_ALGORITHMS.containsKey(algorithm),
        PREFIX + '.' + ALGORITHM,
        "DPoP: unsupported JWS algorithm '%s', must be an RSA or EC algorithm",
        algorithm.getName());
    validator.checkAlgorithm(algorithm);
    if (getPrivateKey().isPresent()) {
      validator.check(
          Files.isRegularFile(getPrivateKey().get()) && Files.isReadable(getPrivateKey().get()),
          PREFIX + '.' + PRIVATE_KEY,
          "DPoP: private key path '%s' is not a file or is not readable",
          getPrivateKey().get());
    }
    if (getPublicKey().isPresent()) {
      validator.check(
          Files.isRegularFile(getPublicKey().get()) && Files.isReadable(getPublicKey().get()),
          PREFIX + '.' + PUBLIC_KEY,
          "DPoP: public key path '%s' is not a file or is not readable",
          getPublicKey().get());
    }
    validator.validate();
  }
}
