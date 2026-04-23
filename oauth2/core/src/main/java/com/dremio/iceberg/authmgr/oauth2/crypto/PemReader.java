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
package com.dremio.iceberg.authmgr.oauth2.crypto;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;

/** A reader for PEM files. */
public interface PemReader {

  static PemReader getInstance() {
    return PemReaderInternal.INSTANCE;
  }

  /**
   * Reads a private key from a PEM file.
   *
   * <p>RSA and ECDSA keys in the PKCS#8 format are always supported.
   *
   * <p>Support for additional key formats, such as RSA in the PKCS#1 format or ECDSA keys in SEC 1
   * format, is supported if the BouncyCastle library is available.
   *
   * <p>Only unencrypted keys are supported.
   *
   * @param file the path to the PEM file containing the private key
   * @return the private key
   * @throws IllegalArgumentException if the file cannot be read, parsed, or doesn't contain a valid
   *     private key
   */
  PrivateKey readPrivateKey(Path file);

  /**
   * Reads a public key from a PEM file.
   *
   * <p>RSA and ECDSA public keys in X.509 SubjectPublicKeyInfo format ({@code -----BEGIN PUBLIC
   * KEY-----}, as produced by {@code openssl pkey -pubout}) are always supported.
   *
   * @param file the path to the PEM file containing the public key
   * @return the public key
   * @throws IllegalArgumentException if the file cannot be read or parsed, or doesn't contain a
   *     valid public key
   */
  PublicKey readPublicKey(Path file);

  /**
   * Derives the public key corresponding to the given private key.
   *
   * <p>For RSA keys, derivation is possible with any JCA-compliant runtime: the modulus and public
   * exponent are available from a standard PKCS#8-loaded {@link
   * java.security.interfaces.RSAPrivateCrtKey}.
   *
   * <p>For EC keys, derivation requires elliptic-curve point multiplication, which the standard JCA
   * API does not expose. Implementations that do not have access to an EC arithmetic library MUST
   * throw {@link IllegalStateException}.
   *
   * @param privateKey the private key
   * @return the corresponding public key
   * @throws IllegalStateException if the public key cannot be derived (e.g. EC without a suitable
   *     library)
   * @throws IllegalArgumentException if the private key type is not supported
   */
  PublicKey derivePublicKey(PrivateKey privateKey);
}

final class PemReaderInternal {

  static final PemReader INSTANCE = selectImpl();

  private static PemReader selectImpl() {
    try {
      Class.forName("org.bouncycastle.openssl.PEMParser");
      return new BouncyCastlePemReader();
    } catch (ClassNotFoundException e) {
      return new JcaPemReader();
    }
  }
}
