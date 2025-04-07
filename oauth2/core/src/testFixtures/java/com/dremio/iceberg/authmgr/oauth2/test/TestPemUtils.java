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
package com.dremio.iceberg.authmgr.oauth2.test;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class TestPemUtils {

  private static volatile KeyPair keyPair;

  /** Copies a PEM-formatted private key to the specified destination file. */
  public static void copyPrivateKey(Path destination) {
    try {
      PrivateKey privateKey = getKeyPair().getPrivate();
      String privateKeyPem = formatKeyAsPem(privateKey);
      try (BufferedWriter writer = Files.newBufferedWriter(destination, StandardCharsets.UTF_8)) {
        writer.write(privateKeyPem);
      }
    } catch (NoSuchAlgorithmException | IOException e) {
      throw new RuntimeException("Failed to write private key to " + destination, e);
    }
  }

  /**
   * Generates a self-signed X.509 certificate for the given common name.
   *
   * @param commonName the common name (CN) to use in the certificate subject
   */
  public static X509Certificate generateSelfSignedCertificate(String commonName) {
    X500Principal subject = new X500Principal("CN=" + commonName);
    BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
    Instant now = Instant.now();
    Date notBefore = Date.from(now);
    Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));
    try {
      X509v3CertificateBuilder certificateBuilder =
          new JcaX509v3CertificateBuilder(
              subject, serialNumber, notBefore, notAfter, subject, getKeyPair().getPublic());
      ContentSigner contentSigner =
          new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(getKeyPair().getPrivate());
      return new JcaX509CertificateConverter()
          .getCertificate(certificateBuilder.build(contentSigner));
    } catch (Exception e) {
      throw new RuntimeException("Failed to generate certificate", e);
    }
  }

  /**
   * Returns a Base64-encoded X.509 certificate without PEM headers/footers. This is the format
   * expected by Keycloak.
   *
   * @param commonName the common name (CN) to use in the certificate subject
   * @return Base64-encoded certificate content without PEM headers/footers
   */
  public static String encodedSelfSignedCertificate(String commonName) {
    X509Certificate cert = generateSelfSignedCertificate(commonName);
    try {
      return Base64.getMimeEncoder().encodeToString(cert.getEncoded());
    } catch (Exception e) {
      throw new RuntimeException("Failed to encode generated certificate", e);
    }
  }

  /** Gets or creates the RSA key pair. Uses double-checked locking for thread-safe lazy init. */
  private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
    KeyPair result = keyPair;
    if (result == null) {
      synchronized (TestPemUtils.class) {
        result = keyPair;
        if (result == null) {
          KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
          keyPairGenerator.initialize(2048);
          keyPair = result = keyPairGenerator.generateKeyPair();
        }
      }
    }
    return result;
  }

  private static String formatKeyAsPem(Key privateKey) {
    return "-----BEGIN PRIVATE KEY-----\n"
        + Base64.getMimeEncoder().encodeToString(privateKey.getEncoded())
        + "\n-----END PRIVATE KEY-----";
  }

  private TestPemUtils() {}
}
