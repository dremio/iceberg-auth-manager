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

import com.dremio.iceberg.authmgr.oauth2.test.TestCryptoUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BouncyCastleCryptoProviderTest {

  @TempDir Path tempDir;

  @Test
  void testReadPkcs8PrivateKey() {
    // Given
    Path privateKeyFile = tempDir.resolve("testReadPkcs8PrivateKey.pem");
    TestCryptoUtils.writeSelfSignedCertificate(privateKeyFile); // should be ignored
    TestCryptoUtils.writePkcs8PrivateKey(privateKeyFile);

    // When
    RSAPrivateKey privateKey = new BouncyCastleCryptoProvider().readPrivateKey(privateKeyFile);

    // Then
    assertThat(privateKey).isNotNull();
    assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
    assertThat(privateKey.getModulus()).isNotNull();
    assertThat(privateKey.getPrivateExponent()).isNotNull();
    assertThat(privateKey.getModulus().bitLength()).isEqualTo(2048);
  }

  @Test
  void testReadPkcs1RsaPrivateKey() {
    // Given
    Path privateKeyFile = tempDir.resolve("testReadPkcs1RsaPrivateKey.pem");
    TestCryptoUtils.writeSelfSignedCertificate(privateKeyFile); // should be ignored
    TestCryptoUtils.writePkcs1PrivateKey(privateKeyFile);

    // When
    RSAPrivateKey privateKey = new BouncyCastleCryptoProvider().readPrivateKey(privateKeyFile);

    // Then
    assertThat(privateKey).isNotNull();
    assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
    assertThat(privateKey.getModulus()).isNotNull();
    assertThat(privateKey.getPrivateExponent()).isNotNull();
    assertThat(privateKey.getModulus().bitLength()).isEqualTo(2048);
  }

  @Test
  void testReadNonExistentFile() {
    // Given
    Path nonExistentFile = tempDir.resolve("non-existent.pem");

    // When - Then
    assertThatThrownBy(() -> new BouncyCastleCryptoProvider().readPrivateKey(nonExistentFile))
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
    assertThatThrownBy(() -> new BouncyCastleCryptoProvider().readPrivateKey(emptyFile))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("No private key found in file");
  }

  @Test
  void testReadFileWithoutPrivateKey() {

    // Given
    Path privateKeyFile = tempDir.resolve("testReadFileWithoutPrivateKey.pem");
    TestCryptoUtils.writeSelfSignedCertificate(privateKeyFile); // should be ignored

    // When - Then
    assertThatThrownBy(() -> new BouncyCastleCryptoProvider().readPrivateKey(privateKeyFile))
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
    assertThatThrownBy(() -> new BouncyCastleCryptoProvider().readPrivateKey(invalidFile))
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
    assertThatThrownBy(() -> new BouncyCastleCryptoProvider().readPrivateKey(invalidBase64File))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("invalid characters encountered in base64 data");
  }
}
