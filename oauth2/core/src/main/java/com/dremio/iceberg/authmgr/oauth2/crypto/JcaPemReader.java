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

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;

final class JcaPemReader implements PemReader {

  private static final String[] ALGORITHMS = {"RSA", "EC"};

  @Override
  public PrivateKey readPrivateKey(Path file) {
    try {
      byte[] encoded = Base64.decodeBase64(readPemEncodedPrivateKey(file));
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
      InvalidKeySpecException toThrow = null;
      for (String algorithm : ALGORITHMS) {
        try {
          return KeyFactory.getInstance(algorithm).generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
          if (toThrow == null) {
            toThrow = e;
          } else {
            toThrow.addSuppressed(e);
          }
        }
      }
      throw toThrow;
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + file, e);
    }
  }

  @Override
  public PublicKey readPublicKey(Path file) {
    try {
      byte[] encoded = Base64.decodeBase64(readPemEncodedPublicKey(file));
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
      InvalidKeySpecException toThrow = null;
      for (String algorithm : ALGORITHMS) {
        try {
          return KeyFactory.getInstance(algorithm).generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
          if (toThrow == null) {
            toThrow = e;
          } else {
            toThrow.addSuppressed(e);
          }
        }
      }
      throw toThrow;
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + file, e);
    }
  }

  @Override
  public PublicKey derivePublicKey(PrivateKey privateKey) {
    if (privateKey instanceof RSAPrivateCrtKey) {
      return deriveRsaPublicKey((RSAPrivateCrtKey) privateKey);
    }
    if (privateKey instanceof ECPrivateKey) {
      throw new IllegalStateException(
          "Deriving an EC public key from a private key requires BouncyCastle on the classpath");
    }
    throw new IllegalArgumentException(
        "Unsupported private key type: " + privateKey.getClass().getName());
  }

  private static String readPemEncodedPrivateKey(Path file) throws IOException {
    StringBuilder keyBuilder = new StringBuilder();
    try (BufferedReader reader = Files.newBufferedReader(file)) {
      boolean started = false;
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("-----BEGIN PRIVATE KEY")) {
          started = true;
        } else if (line.startsWith("-----END PRIVATE KEY")) {
          break;
        } else if (started) {
          keyBuilder.append(line.trim());
        }
      }
    }
    if (keyBuilder.length() == 0) {
      throw new IllegalArgumentException("No private key found in file: " + file);
    }
    return keyBuilder.toString();
  }

  private static String readPemEncodedPublicKey(Path file) throws IOException {
    StringBuilder keyBuilder = new StringBuilder();
    try (BufferedReader reader = Files.newBufferedReader(file)) {
      boolean started = false;
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("-----BEGIN PUBLIC KEY")) {
          started = true;
        } else if (line.startsWith("-----END PUBLIC KEY")) {
          break;
        } else if (started) {
          keyBuilder.append(line.trim());
        }
      }
    }
    if (keyBuilder.length() == 0) {
      throw new IllegalArgumentException("No public key found in file: " + file);
    }
    return keyBuilder.toString();
  }

  static PublicKey deriveRsaPublicKey(RSAPrivateCrtKey privateKey) {
    try {
      return KeyFactory.getInstance("RSA")
          .generatePublic(
              new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Failed to derive RSA public key", e);
    }
  }
}
