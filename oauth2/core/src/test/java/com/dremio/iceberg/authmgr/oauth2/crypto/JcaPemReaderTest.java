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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JcaPemReaderTest {

  @TempDir Path tempDir;

  @Test
  void testReadPkcs8RsaPrivateKey() throws IOException {
    // Given
    Path privateKeyFile = copyPemFile("/openssl/rsa_private_key_pkcs8.pem");

    // When
    PrivateKey privateKey = new JcaPemReader().readPrivateKey(privateKeyFile);

    // Then
    assertThat(privateKey).isNotNull();
    assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
    assertThat(privateKey).isInstanceOf(RSAPrivateKey.class);
    assertThat(((RSAPrivateKey) privateKey).getModulus().bitLength()).isEqualTo(2048);
  }

  @Test
  void testReadNonExistentFile() {
    // Given
    Path nonExistentFile = tempDir.resolve("non-existent.pem");

    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(nonExistentFile))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .isInstanceOf(NoSuchFileException.class);
  }

  @Test
  void testReadEmptyFile() throws IOException {
    // Given
    Path emptyFile = tempDir.resolve("empty.pem");
    Files.createFile(emptyFile);

    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(emptyFile))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("No private key found in file");
  }

  @Test
  void testReadFileWithoutPrivateKey() throws IOException {
    // Given
    Path certificateFile = copyPemFile("/openssl/rsa_certificate.pem");

    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(certificateFile))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("No private key found in file");
  }

  @Test
  void testReadInvalidPemContent() throws IOException {
    // Given
    Path invalidFile = tempDir.resolve("invalid.pem");
    Files.writeString(invalidFile, "This is not a valid PEM file content");

    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(invalidFile))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("No private key found in file");
  }

  @Test
  void testReadPemWithInvalidBase64() throws IOException {
    // Given
    Path invalidBase64File = tempDir.resolve("invalid-base64.pem");
    Files.writeString(
        invalidBase64File,
        "-----BEGIN PRIVATE KEY-----\n"
            + "This is not valid base64 content!!!\n"
            + "-----END PRIVATE KEY-----\n");

    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(invalidBase64File))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("not enough content");
  }

  private Path copyPemFile(String resource) throws IOException {
    try (InputStream is = getClass().getResourceAsStream(resource)) {
      Path dest = tempDir.resolve("test.pem");
      Files.copy(Objects.requireNonNull(is), dest);
      return dest;
    }
  }
}
