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

import com.auth0.jwt.algorithms.Algorithm;
import jakarta.annotation.Nullable;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;

/**
 * Supported JSON Web Algorithms (JWA) for JSON Web Signature (JWS).
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section 3.1</a>
 */
public enum JwtSigningAlgorithm {
  HMAC_SHA256("HS256", "HmacSHA256"),
  HMAC_SHA384("HS384", "HmacSHA384"),
  HMAC_SHA512("HS512", "HmacSHA512"),

  RSA_SHA256("RS256", "SHA256withRSA"),
  RSA_SHA384("RS384", "SHA384withRSA"),
  RSA_SHA512("RS512", "SHA512withRSA"),
  ;

  private final String jwsName;
  private final String jcaName;

  JwtSigningAlgorithm(String jwsName, String jcaName) {
    this.jwsName = jwsName;
    this.jcaName = jcaName;
  }

  /**
   * Returns the HMAC Auth0 {@link Algorithm} for this signing algorithm and the given secret.
   *
   * @param secret the secret to use for signing
   * @return the Auth0 algorithm
   * @throws UnsupportedOperationException if this algorithm is not an HMAC algorithm
   */
  public Algorithm getHmacAlgorithm(String secret) {
    switch (this) {
      case HMAC_SHA256:
        return Algorithm.HMAC256(secret);
      case HMAC_SHA384:
        return Algorithm.HMAC384(secret);
      case HMAC_SHA512:
        return Algorithm.HMAC512(secret);
      default:
        throw new UnsupportedOperationException("Unsupported HMAC algorithm: " + this);
    }
  }

  /**
   * Returns the RSA Auth0 {@link Algorithm} for this signing algorithm and the given public and
   * private keys.
   *
   * @param publicKey the public key to use for signing
   * @param privateKey the private key to use for signing
   * @return the Auth0 algorithm
   * @throws UnsupportedOperationException if this algorithm is not an RSA algorithm
   */
  public Algorithm getRsaAlgorithm(
      @Nullable RSAPublicKey publicKey, @Nullable RSAPrivateKey privateKey) {
    switch (this) {
      case RSA_SHA256:
        return Algorithm.RSA256(publicKey, privateKey);
      case RSA_SHA384:
        return Algorithm.RSA384(publicKey, privateKey);
      case RSA_SHA512:
        return Algorithm.RSA512(publicKey, privateKey);
      default:
        throw new UnsupportedOperationException("Unsupported RSA algorithm: " + this);
    }
  }

  /**
   * Returns the JWS name of this algorithm, as defined in <a
   * href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section 3.1</a>.
   */
  public String getJwsName() {
    return jwsName;
  }

  /**
   * Returns the JCA (Java Cryptography Architecture) name of this algorithm, as defined in <a
   * href="https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html">JCA
   * Signature Algorithm Names</a>.
   */
  public String getJcaName() {
    return jcaName;
  }

  public boolean isHmacAlgorithm() {
    return this == HMAC_SHA256 || this == HMAC_SHA384 || this == HMAC_SHA512;
  }

  public boolean isRsaAlgorithm() {
    return this == RSA_SHA256 || this == RSA_SHA384 || this == RSA_SHA512;
  }

  /**
   * Returns the {@link JwtSigningAlgorithm} for the given name. The name can be the JWS name, the
   * JCA name, or the enum name.
   */
  public static JwtSigningAlgorithm fromConfigName(String name) {
    try {
      return valueOf(name.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException ignore) {
      name = name.toLowerCase(Locale.ROOT);
      for (JwtSigningAlgorithm alg : values()) {
        if (alg.jwsName.toLowerCase(Locale.ROOT).equals(name)
            || alg.jcaName.toLowerCase(Locale.ROOT).equals(name)) {
          return alg;
        }
      }
      throw new IllegalArgumentException("Unknown signing algorithm: " + name);
    }
  }
}
