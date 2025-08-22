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
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;

final class JcaPemReader implements PemReader {

  @Override
  public PrivateKey readPrivateKey(Path file) {
    try {
      byte[] encoded = Base64.decodeBase64(readPemEncodedPrivateKey(file));
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
      return keyFactory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + file, e);
    }
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
}
