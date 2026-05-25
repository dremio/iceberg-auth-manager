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
package com.dremio.oauth2.agent.config;

import com.dremio.oauth2.agent.OAuth2AgentConfig;
import com.dremio.oauth2.agent.config.validator.ConfigValidator;
import com.nimbusds.jose.JWSAlgorithm;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

/**
 * Configuration properties for <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449:
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>.
 *
 * <p>When enabled, the agent generates an ephemeral asymmetric keypair and attaches a signed DPoP
 * proof JWT to every request sent to the authorization server's token endpoint, as well as to every
 * authenticated request sent to the protected resource server.
 *
 * <p>DPoP is disabled by default. To enable it, set {@code rest.auth.oauth2.dpop.enabled=true}.
 */
public interface DpopConfig {

  String GROUP_NAME = "dpop";
  String PREFIX = OAuth2AgentConfig.PREFIX + '.' + GROUP_NAME;

  String ENABLED = "enabled";
  String ALGORITHM = "algorithm";

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
    validator.validate();
  }
}
