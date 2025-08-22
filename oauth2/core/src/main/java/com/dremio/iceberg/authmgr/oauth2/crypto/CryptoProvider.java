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
import java.security.interfaces.RSAPrivateKey;
import org.slf4j.LoggerFactory;

/** A provider for cryptographic operations. */
public interface CryptoProvider {

  CryptoProvider INSTANCE = selectProvider();

  private static CryptoProvider selectProvider() {
    CryptoProvider provider;
    try {
      Class.forName("org.bouncycastle.openssl.PEMParser");
      provider = new BouncyCastleCryptoProvider();
    } catch (ClassNotFoundException e) {
      provider = new JcaCryptoProvider();
    }
    LoggerFactory.getLogger(CryptoProvider.class)
        .debug(
            "Using {} for cryptographic operations",
            provider instanceof BouncyCastleCryptoProvider ? "BouncyCastle" : "JCA");
    return provider;
  }

  /**
   * Reads an RSA private key from a PEM file. At least the PKCS#8 format is always supported.
   * PKCS#1 is supported if the BouncyCastle library is available.
   *
   * <p>Only unencrypted keys are supported.
   *
   * @param file the path to the PEM file containing the private key
   * @return the RSA private key
   * @throws IllegalArgumentException if the file cannot be read, parsed, or doesn't contain a valid
   *     RSA private key
   */
  RSAPrivateKey readPrivateKey(Path file);
}
