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

import com.dremio.iceberg.authmgr.oauth2.test.TestCertificates;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class JcaPemReaderTest {

  @TempDir Path tempDir;

  @Test
  void testReadPkcs8RsaPrivateKey() {
    // Given
    Path privateKeyFile = TestCertificates.instance().getRsaPrivateKeyPkcs8Pem();

    // When
    PrivateKey privateKey = new JcaPemReader().readPrivateKey(privateKeyFile);

    // Then
    assertThat(privateKey).isNotNull();
    assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
    assertThat(privateKey).isInstanceOf(RSAPrivateKey.class);
    assertThat(((RSAPrivateKey) privateKey).getModulus().bitLength()).isEqualTo(2048);
  }

  @Test
  void testReadEcPkcs8PrivateKey() {
    // Given
    Path privateKeyFile = TestCertificates.instance().getEcdsaPrivateKeyPkcs8Pem();

    // When
    PrivateKey privateKey = new JcaPemReader().readPrivateKey(privateKeyFile);

    // Then
    assertThat(privateKey).isNotNull();
    assertThat(privateKey.getAlgorithm()).isEqualTo("EC");
    assertThat(privateKey).isInstanceOf(ECPrivateKey.class);
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

  @ParameterizedTest
  @MethodSource("invalidPemFiles")
  void testReadFileWithoutPrivateKey(Path certificateFile) {
    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(certificateFile))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("No private key found in file");
  }

  static Stream<Path> invalidPemFiles() {
    return Stream.of(
        TestCertificates.instance().getRsaPublicKeyPem(),
        TestCertificates.instance().getRsaCertificatePem(),
        TestCertificates.instance().getEcdsaPublicKeyPem(),
        TestCertificates.instance().getEcdsaCertificatePem());
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
        """
            -----BEGIN PRIVATE KEY-----
            This is not valid base64 content!!!
            -----END PRIVATE KEY-----
            """);

    // When - Then
    assertThatThrownBy(() -> new JcaPemReader().readPrivateKey(invalidBase64File))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Failed to read PEM file")
        .rootCause()
        .hasMessageContaining("not enough content");
  }
}
