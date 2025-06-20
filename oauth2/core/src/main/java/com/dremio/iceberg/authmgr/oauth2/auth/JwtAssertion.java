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
package com.dremio.iceberg.authmgr.oauth2.auth;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * The contents of a JWT assertion as specified in <a
 * href="https://datatracker.ietf.org/doc/html/rfc7523#section-3">RFC 7523 Section 3</a>.
 */
public interface JwtAssertion {

  /**
   * The issuer of the client assertion JWT. Optional. The default is the client ID.
   *
   * @see ClientAssertion#ISSUER
   */
  Optional<String> getIssuer();

  /**
   * The subject of the client assertion JWT. Optional. The default is the client ID.
   *
   * @see ClientAssertion#SUBJECT
   */
  Optional<String> getSubject();

  /**
   * The audience of the client assertion JWT. Optional. The default is the token endpoint.
   *
   * @see ClientAssertion#AUDIENCE
   */
  Optional<String> getAudience();

  /**
   * The lifespan of the client assertion JWT. Optional. The default is 5 minutes.
   *
   * @see ClientAssertion#TOKEN_LIFESPAN
   */
  Optional<Duration> getTokenLifespan();

  /**
   * Extra claims to include in the client assertion JWT. Optional. The default is empty.
   *
   * @see ClientAssertion#EXTRA_CLAIMS_PREFIX
   */
  Map<String, String> getExtraClaims();

  /**
   * The signing algorithm to use for the client assertion JWT. Optional. The default is "HS256" if
   * the authentication method is "client_secret_jwt", or "RS256" if the authentication method is
   * "private_key_jwt".
   *
   * <p>Algorithm names must match either the JWS name or the JCA name of the algorithm.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section
   *     3.1</a>
   * @see ClientAssertion#ALGORITHM
   */
  Optional<JwtSigningAlgorithm> getAlgorithm();

  /**
   * The path on the local filesystem to the private key to use for signing the client assertion
   * JWT. Required if the authentication method is "private_key_jwt". The file must be in PEM
   * format; it may contain a private key, or a private key and a certificate chain. Only the
   * private key is used.
   *
   * @see ClientAssertion#PRIVATE_KEY
   */
  Optional<Path> getPrivateKey();
}
