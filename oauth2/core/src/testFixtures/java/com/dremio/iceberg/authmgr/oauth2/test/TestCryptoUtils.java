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

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;

public final class TestCryptoUtils {

  /**
   * Test RSA key pair used for generating private keys and self-signed certificates. Lazily
   * initialized on first use.
   */
  private static final Supplier<KeyPair> KEY_PAIR =
      Suppliers.memoize(
          () -> {
            try {
              KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
              generator.initialize(2048);
              return generator.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
              throw new RuntimeException("Failed to get RSA KeyPairGenerator", e);
            }
          });

  /** Writes the private key as a PKCS#8 PEM-encoded file to the specified destination. */
  public static void writePkcs8PrivateKey(Path destination) {
    try (BufferedWriter writer =
            Files.newBufferedWriter(
                destination,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      PrivateKey privateKey = KEY_PAIR.get().getPrivate();
      PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
      pemWriter.writeObject(pemObject);
    } catch (IOException e) {
      throw new RuntimeException("Failed to write PKCS#8 private key to " + destination, e);
    }
  }

  /** Writes the private key as a PKCS#1 PEM-encoded file to the specified destination. */
  public static void writePkcs1PrivateKey(Path destination) {
    try (BufferedWriter writer =
            Files.newBufferedWriter(
                destination,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      PrivateKey privateKey = KEY_PAIR.get().getPrivate();
      byte[] pkcs1Bytes =
          PrivateKeyInfo.getInstance(privateKey.getEncoded())
              .parsePrivateKey()
              .toASN1Primitive()
              .getEncoded();
      PemObject pemObject = new PemObject("RSA PRIVATE KEY", pkcs1Bytes);
      pemWriter.writeObject(pemObject);
    } catch (Exception e) {
      throw new RuntimeException("Failed to write PKCS#1 private key to " + destination, e);
    }
  }

  /** Writes a self-signed certificate to the specified destination. */
  public static void writeSelfSignedCertificate(Path destination) {
    try (BufferedWriter writer =
            Files.newBufferedWriter(
                destination,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND,
                StandardOpenOption.WRITE);
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      X509Certificate cert = generateSelfSignedCertificate("test");
      pemWriter.writeObject(cert);
    } catch (IOException e) {
      throw new RuntimeException("Failed to write certificate to " + destination, e);
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
              subject, serialNumber, notBefore, notAfter, subject, KEY_PAIR.get().getPublic());
      ContentSigner contentSigner =
          new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(KEY_PAIR.get().getPrivate());
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

  private TestCryptoUtils() {}
}
