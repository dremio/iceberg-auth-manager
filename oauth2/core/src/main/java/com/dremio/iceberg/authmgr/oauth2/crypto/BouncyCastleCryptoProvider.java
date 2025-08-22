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

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

final class BouncyCastleCryptoProvider implements CryptoProvider {

  BouncyCastleCryptoProvider() {}

  /**
   * Reads an RSA private key from a PEM file. Supported PEM formats:
   *
   * <ul>
   *   <li>RSA Private Key file (PKCS#1) - BEGIN RSA PRIVATE KEY
   *   <li>Private Key file (PKCS#8) - BEGIN PRIVATE KEY
   * </ul>
   *
   * Only unencrypted keys are supported.
   *
   * @param file the path to the PEM file containing the private key
   * @return the RSA private key
   * @throws IllegalArgumentException if the file cannot be read, parsed, or doesn't contain a valid
   *     RSA private key
   */
  @Override
  public RSAPrivateKey readPrivateKey(Path file) {
    try (Reader reader = Files.newBufferedReader(file);
        PEMParser pemParser = new PEMParser(reader)) {

      Object pemObject;
      while ((pemObject = pemParser.readObject()) != null) {

        PrivateKey privateKey = extractPrivateKey(pemObject);

        if (privateKey != null) {
          if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException(
                "Expected RSA private key, but found: " + privateKey);
          }
          return (RSAPrivateKey) privateKey;
        }
      }

      throw new IllegalArgumentException("No private key found in file: " + file);

    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + file, e);
    }
  }

  private static PrivateKey extractPrivateKey(Object pemObject) throws PEMException {
    if (pemObject instanceof PEMKeyPair) {
      // Handle PKCS#1 RSA format (BEGIN RSA PRIVATE KEY)
      return new JcaPEMKeyConverter().getPrivateKey(((PEMKeyPair) pemObject).getPrivateKeyInfo());

    } else if (pemObject instanceof PrivateKeyInfo) {
      // Handle PKCS#8 format (BEGIN PRIVATE KEY)
      return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) pemObject);
    }
    return null;
  }
}
