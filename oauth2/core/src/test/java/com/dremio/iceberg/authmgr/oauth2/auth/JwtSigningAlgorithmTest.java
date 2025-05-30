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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class JwtSigningAlgorithmTest {

  @ParameterizedTest
  @CsvSource({
    "HS256         , HMAC_SHA256",
    "HMAC_SHA256   , HMAC_SHA256",
    "HmacSHA256    , HMAC_SHA256",
    "HS384         , HMAC_SHA384",
    "HMAC_SHA384   , HMAC_SHA384",
    "HmacSHA384    , HMAC_SHA384",
    "HMAC_SHA512   , HMAC_SHA512",
    "HS512         , HMAC_SHA512",
    "HmacSHA512    , HMAC_SHA512",
    "RS256         , RSA_SHA256",
    "RSA_SHA256    , RSA_SHA256",
    "SHA256withRSA , RSA_SHA256",
    "RS384         , RSA_SHA384",
    "RSA_SHA384    , RSA_SHA384",
    "SHA384withRSA , RSA_SHA384",
    "RS512         , RSA_SHA512",
    "RSA_SHA512    , RSA_SHA512",
    "SHA512withRSA , RSA_SHA512",
  })
  void fromConfigName(String name, JwtSigningAlgorithm expected) {
    assertThat(JwtSigningAlgorithm.fromConfigName(name)).isEqualTo(expected);
    assertThat(JwtSigningAlgorithm.fromConfigName(name.toLowerCase(Locale.ROOT)))
        .isEqualTo(expected);
    assertThat(JwtSigningAlgorithm.fromConfigName(name.toUpperCase(Locale.ROOT)))
        .isEqualTo(expected);
  }

  @Test
  void isHmacAlgorithm() {
    assertThat(JwtSigningAlgorithm.HMAC_SHA256.isHmacAlgorithm()).isTrue();
    assertThat(JwtSigningAlgorithm.HMAC_SHA384.isHmacAlgorithm()).isTrue();
    assertThat(JwtSigningAlgorithm.HMAC_SHA512.isHmacAlgorithm()).isTrue();
    assertThat(JwtSigningAlgorithm.RSA_SHA256.isHmacAlgorithm()).isFalse();
    assertThat(JwtSigningAlgorithm.RSA_SHA384.isHmacAlgorithm()).isFalse();
    assertThat(JwtSigningAlgorithm.RSA_SHA512.isHmacAlgorithm()).isFalse();
  }

  @Test
  void isRsaAlgorithm() {
    assertThat(JwtSigningAlgorithm.HMAC_SHA256.isRsaAlgorithm()).isFalse();
    assertThat(JwtSigningAlgorithm.HMAC_SHA384.isRsaAlgorithm()).isFalse();
    assertThat(JwtSigningAlgorithm.HMAC_SHA512.isRsaAlgorithm()).isFalse();
    assertThat(JwtSigningAlgorithm.RSA_SHA256.isRsaAlgorithm()).isTrue();
    assertThat(JwtSigningAlgorithm.RSA_SHA384.isRsaAlgorithm()).isTrue();
    assertThat(JwtSigningAlgorithm.RSA_SHA512.isRsaAlgorithm()).isTrue();
  }

  @Test
  void hmacAlgorithms() {
    String secret = "test-secret";
    assertThat(JwtSigningAlgorithm.HMAC_SHA256.getHmacAlgorithm(secret)).isNotNull();
    assertThat(JwtSigningAlgorithm.HMAC_SHA384.getHmacAlgorithm(secret)).isNotNull();
    assertThat(JwtSigningAlgorithm.HMAC_SHA512.getHmacAlgorithm(secret)).isNotNull();
    assertThatThrownBy(() -> JwtSigningAlgorithm.RSA_SHA256.getHmacAlgorithm(secret))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> JwtSigningAlgorithm.RSA_SHA384.getHmacAlgorithm(secret))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> JwtSigningAlgorithm.RSA_SHA512.getHmacAlgorithm(secret))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void rsaAlgorithms() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    assertThat(JwtSigningAlgorithm.RSA_SHA256.getRsaAlgorithm(publicKey, privateKey)).isNotNull();
    assertThat(JwtSigningAlgorithm.RSA_SHA384.getRsaAlgorithm(publicKey, privateKey)).isNotNull();
    assertThat(JwtSigningAlgorithm.RSA_SHA512.getRsaAlgorithm(publicKey, privateKey)).isNotNull();
    assertThatThrownBy(() -> JwtSigningAlgorithm.HMAC_SHA256.getRsaAlgorithm(publicKey, privateKey))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> JwtSigningAlgorithm.HMAC_SHA384.getRsaAlgorithm(publicKey, privateKey))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> JwtSigningAlgorithm.HMAC_SHA512.getRsaAlgorithm(publicKey, privateKey))
        .isInstanceOf(UnsupportedOperationException.class);
  }
}
