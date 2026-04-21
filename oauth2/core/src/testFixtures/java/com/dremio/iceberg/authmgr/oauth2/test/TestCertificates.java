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

import com.dremio.iceberg.authmgr.oauth2.crypto.PemReader;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Generates test certificates and keystores at runtime. All materials are generated lazily (once
 * per JVM) and stored in a temp directory.
 *
 * <p>The material is divided in 2 main groups: one is based on RSA keys, the second on ECDSA keys.
 * Each group exposes: a key pair, a self-signed certificate, PEM-encoded files, and a PKCS#12
 * keystore containing all the material.
 *
 * <p>Most of the material (RSA/ECDSA key pairs, PKCS#8 PEM, PKCS#12 keystores) is generated using
 * standard JCA APIs, with two exceptions:
 *
 * <ol>
 *   <li>Self-signed certificates are generated using {@code keytool} since self-signed certificate
 *       creation has no standard JCA API.
 *   <li>PKCS#1 and SEC 1 PEM formats require BouncyCastle and are generated lazily on first access
 *       via {@link BouncyCastleHelper}.
 * </ol>
 *
 * <p>Finally, this class also exposes the MockServer key and certificate materials as a PKCS#12
 * keystore, for convenience. This requires MockServer on the classpath and is also generated
 * lazily.
 */
public final class TestCertificates {

  private static final class Holder {
    private static final TestCertificates INSTANCE = new TestCertificates();
  }

  public static TestCertificates instance() {
    return Holder.INSTANCE;
  }

  private static final String ALIAS = "1";

  // Base directory for all generated materials
  private final Path baseDir;

  // The password for all keystores
  private final String keystorePassword = UUID.randomUUID().toString();

  private final boolean bouncyCastleAvailable;

  // RSA
  private final PrivateKey rsaPrivateKey;
  private final X509Certificate rsaCertificate;
  private final Path rsaPublicKeyPkcs8Pem;
  private final Path rsaPrivateKeyPkcs8Pem;
  private final Path rsaCertificatePem;
  private final Path rsaKeyStoreP12;

  // ECDSA
  private final PrivateKey ecdsaPrivateKey;
  private final X509Certificate ecdsaCertificate;
  private final Path ecdsaPublicKeyPkcs8Pem;
  private final Path ecdsaPrivateKeyPkcs8Pem;
  private final Path ecdsaCertificatePem;
  private final Path ecdsaKeyStoreP12;

  // Lazily generated (require BouncyCastle)
  private volatile Path rsaPrivateKeyPkcs1Pem;
  private volatile Path ecdsaPrivateKeySec1Pem;

  // Lazily generated (require MockServer)
  private volatile Path mockServerP12;

  private TestCertificates() {
    try {
      baseDir = Files.createTempDirectory("authmgr-test-certs");
      Runtime.getRuntime()
          .addShutdownHook(
              new Thread(
                  () -> {
                    try {
                      MoreFiles.deleteRecursively(baseDir, RecursiveDeleteOption.ALLOW_INSECURE);
                    } catch (IOException ignored) {
                      // best effort
                    }
                  }));

      bouncyCastleAvailable = probeForBouncyCastle();

      // Generate RSA material
      rsaKeyStoreP12 = baseDir.resolve("keystore.p12");
      runKeytool(rsaKeyStoreP12, "RSA", "2048", "SHA256withRSA");
      KeyStore rsaKs = loadKeyStore(rsaKeyStoreP12);

      rsaCertificate = (X509Certificate) rsaKs.getCertificate(ALIAS);
      rsaCertificatePem = baseDir.resolve("rsa_certificate.pem");
      writeCertificatePem(rsaCertificate, rsaCertificatePem);

      rsaPublicKeyPkcs8Pem = baseDir.resolve("rsa_public_key_pkcs8.pem");
      writePkcs8Pem(rsaCertificate.getPublicKey(), rsaPublicKeyPkcs8Pem);

      rsaPrivateKey = (PrivateKey) rsaKs.getKey(ALIAS, keystorePassword.toCharArray());
      rsaPrivateKeyPkcs8Pem = baseDir.resolve("rsa_private_key_pkcs8.pem");
      writePkcs8Pem(rsaPrivateKey, rsaPrivateKeyPkcs8Pem);

      // Generate ECDSA material
      ecdsaKeyStoreP12 = baseDir.resolve("ec_keystore.p12");
      runKeytool(ecdsaKeyStoreP12, "EC", "secp256r1", "SHA256withECDSA");
      KeyStore ecKs = loadKeyStore(ecdsaKeyStoreP12);

      ecdsaCertificate = (X509Certificate) ecKs.getCertificate(ALIAS);
      ecdsaCertificatePem = baseDir.resolve("ecdsa_certificate.pem");
      writeCertificatePem(ecdsaCertificate, ecdsaCertificatePem);

      ecdsaPublicKeyPkcs8Pem = baseDir.resolve("ecdsa_public_key_pkcs8.pem");
      writePkcs8Pem(ecdsaCertificate.getPublicKey(), ecdsaPublicKeyPkcs8Pem);

      ecdsaPrivateKey = (PrivateKey) ecKs.getKey(ALIAS, keystorePassword.toCharArray());
      ecdsaPrivateKeyPkcs8Pem = baseDir.resolve("ecdsa_private_key_pkcs8.pem");
      writePkcs8Pem(ecdsaPrivateKey, ecdsaPrivateKeyPkcs8Pem);

    } catch (Exception e) {
      throw new RuntimeException("Failed to generate test certificates", e);
    }
  }

  /** Whether BouncyCastle is available on the classpath. */
  public boolean isBouncyCastleAvailable() {
    return bouncyCastleAvailable;
  }

  /** The keystore password used for all keystores. */
  public String getKeyStorePassword() {
    return keystorePassword;
  }

  // RSA Material

  /** RSA certificate object. */
  public X509Certificate getRsaCertificate() {
    return rsaCertificate;
  }

  /** RSA public key object. */
  public PublicKey getRsaPublicKey() {
    return getRsaCertificate().getPublicKey();
  }

  /** RSA private key object. */
  public PrivateKey getRsaPrivateKey() {
    return rsaPrivateKey;
  }

  /** Self-signed RSA certificate in PEM format. */
  public Path getRsaCertificatePem() {
    return rsaCertificatePem;
  }

  /** RSA certificate as a base64-encoded string (no PEM headers), for Keycloak. */
  public String getRsaCertificateBase64() {
    return certificateBase64(getRsaCertificate());
  }

  /** RSA public key in PEM format ({@code BEGIN PUBLIC KEY}). */
  public Path getRsaPublicKeyPem() {
    return rsaPublicKeyPkcs8Pem;
  }

  /** RSA private key in PKCS#8 PEM format ({@code BEGIN PRIVATE KEY}). */
  public Path getRsaPrivateKeyPkcs8Pem() {
    return rsaPrivateKeyPkcs8Pem;
  }

  /**
   * RSA private key in PKCS#1 PEM format ({@code BEGIN RSA PRIVATE KEY}). Requires BouncyCastle on
   * the classpath; generated lazily on first access.
   */
  public Path getRsaPrivateKeyPkcs1Pem() {
    if (rsaPrivateKeyPkcs1Pem == null) {
      synchronized (this) {
        if (rsaPrivateKeyPkcs1Pem == null) {
          try {
            Path path = baseDir.resolve("rsa_private_key_pkcs1.pem");
            BouncyCastleHelper.writePkcs1Pem(getRsaPrivateKey(), path);
            rsaPrivateKeyPkcs1Pem = path;
          } catch (Exception e) {
            throw new RuntimeException("Failed to generate PKCS#1 PEM (requires BouncyCastle)", e);
          }
        }
      }
    }
    return rsaPrivateKeyPkcs1Pem;
  }

  /** PKCS#12 keystore containing the RSA private key and certificate. */
  public Path getRsaKeyStore() {
    return rsaKeyStoreP12;
  }

  // ECDSA Material

  /** ECDSA certificate object. */
  public X509Certificate getEcdsaCertificate() {
    return ecdsaCertificate;
  }

  /** ECDSA public key object. */
  public PublicKey getEcdsaPublicKey() {
    return getEcdsaCertificate().getPublicKey();
  }

  /** ECDSA private key object. */
  public PrivateKey getEcdsaPrivateKey() {
    return ecdsaPrivateKey;
  }

  /** Self-signed ECDSA certificate in PEM format. */
  public Path getEcdsaCertificatePem() {
    return ecdsaCertificatePem;
  }

  /** ECDSA certificate as a base64-encoded string (no PEM headers), for Keycloak. */
  public String getEcdsaCertificateBase64() {
    return certificateBase64(getEcdsaCertificate());
  }

  /** ECDSA public key in PEM format ({@code BEGIN PUBLIC KEY}). */
  public Path getEcdsaPublicKeyPem() {
    return ecdsaPublicKeyPkcs8Pem;
  }

  /** ECDSA private key in PKCS#8 PEM format ({@code BEGIN PRIVATE KEY}). */
  public Path getEcdsaPrivateKeyPkcs8Pem() {
    return ecdsaPrivateKeyPkcs8Pem;
  }

  /**
   * ECDSA private key in SEC 1 PEM format ({@code BEGIN EC PRIVATE KEY}). Requires BouncyCastle on
   * the classpath; generated lazily on first access.
   */
  public Path getEcdsaPrivateKeySec1Pem() {
    if (ecdsaPrivateKeySec1Pem == null) {
      synchronized (this) {
        if (ecdsaPrivateKeySec1Pem == null) {
          try {
            Path path = baseDir.resolve("ecdsa_private_key_sec1.pem");
            BouncyCastleHelper.writeEcPrivateKeyPem(getEcdsaPrivateKey(), path);
            ecdsaPrivateKeySec1Pem = path;
          } catch (Exception e) {
            throw new RuntimeException(
                "Failed to generate EC SEC 1 PEM (requires BouncyCastle)", e);
          }
        }
      }
    }
    return ecdsaPrivateKeySec1Pem;
  }

  /** PKCS#12 keystore containing the ECDSA private key and certificate. */
  public Path getEcdsaKeyStore() {
    return ecdsaKeyStoreP12;
  }

  // MockServer material

  /**
   * PKCS#12 keystore containing MockServer's CA certificate and private key. Requires MockServer on
   * the classpath; generated lazily on first access.
   */
  public Path getMockServerKeyStore() {
    if (mockServerP12 == null) {
      synchronized (this) {
        if (mockServerP12 == null) {
          try {
            Path path = baseDir.resolve("mockserver.p12");
            writeMockServerKeyStore(path);
            mockServerP12 = path;
          } catch (Exception e) {
            throw new RuntimeException("Failed to generate MockServer keystore", e);
          }
        }
      }
    }
    return mockServerP12;
  }

  /**
   * Keytool-based key pair and certificate generation.
   *
   * <p>Standard JCA can generate key pairs (KeyPairGenerator) but has no API for creating
   * self-signed X.509 certificates.
   *
   * <p>The alternatives are BouncyCastle (JcaX509v3CertificateBuilder), the internal
   * sun.security.x509 API (stable but non-public, requires --add-exports), or keytool. Keytool is
   * the least invasive option.
   */
  private void runKeytool(Path keyStorePath, String keyAlg, String keySpec, String sigAlg)
      throws Exception {
    String keytool =
        Path.of(System.getProperty("java.home"), "bin", "keytool").toAbsolutePath().toString();
    List<String> command = new ArrayList<>();
    command.add(keytool);
    command.add("-genkeypair");
    command.add("-keystore");
    command.add(keyStorePath.toAbsolutePath().toString());
    command.add("-storetype");
    command.add("PKCS12");
    command.add("-storepass");
    command.add(keystorePassword);
    command.add("-keypass");
    command.add(keystorePassword);
    command.add("-alias");
    command.add(ALIAS);
    command.add("-keyalg");
    command.add(keyAlg);
    if ("RSA".equals(keyAlg)) {
      command.add("-keysize");
      command.add(keySpec);
    } else if ("EC".equals(keyAlg)) {
      command.add("-groupname");
      command.add(keySpec);
    }
    command.add("-sigalg");
    command.add(sigAlg);
    command.add("-validity");
    command.add("36500");
    command.add("-dname");
    command.add("CN=localhost");
    command.add("-ext");
    command.add("SAN=dns:localhost,ip:127.0.0.1");
    // Basic Constraints X.509 extension, marking the certificate as a CA certificate
    command.add("-ext");
    command.add("BC=ca:true");

    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    int exitCode = process.waitFor();
    if (exitCode != 0) {
      throw new RuntimeException("keytool failed (exit code " + exitCode + "): " + output);
    }
  }

  private void writeMockServerKeyStore(Path path) throws Exception {
    X509Certificate cert;
    try (InputStream certStream =
        TestCertificates.class.getResourceAsStream(
            "/org/mockserver/socket/CertificateAuthorityCertificate.pem")) {
      if (certStream == null) {
        throw new IllegalStateException("MockServer CA certificate not found on classpath.");
      }
      cert =
          (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);
    }
    // Write the MockServer CA private key (PKCS#8 format) to a temp file so PemReader can read it.
    Path keyPemFile = baseDir.resolve("mockserver_ca_key.pem");
    try (InputStream keyStream =
        TestCertificates.class.getResourceAsStream(
            "/org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem")) {
      if (keyStream == null) {
        throw new IllegalStateException("MockServer CA private key not found on classpath.");
      }
      Files.copy(keyStream, keyPemFile);
    }
    PrivateKey key = PemReader.getInstance().readPrivateKey(keyPemFile);
    writeKeyStore(path, key, cert);
  }

  private KeyStore loadKeyStore(Path path) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream is = Files.newInputStream(path)) {
      ks.load(is, keystorePassword.toCharArray());
    }
    return ks;
  }

  private void writeKeyStore(Path path, PrivateKey key, X509Certificate cert) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    ks.setKeyEntry(ALIAS, key, keystorePassword.toCharArray(), new Certificate[] {cert});
    try (OutputStream os = Files.newOutputStream(path)) {
      ks.store(os, keystorePassword.toCharArray());
    }
  }

  private static void writePkcs8Pem(PublicKey key, Path path) throws IOException {
    String pem = toPem("PUBLIC KEY", key.getEncoded());
    Files.writeString(path, pem);
  }

  private static void writePkcs8Pem(PrivateKey key, Path path) throws IOException {
    String pem = toPem("PRIVATE KEY", key.getEncoded());
    Files.writeString(path, pem);
  }

  private static void writeCertificatePem(X509Certificate certificate, Path path)
      throws IOException {
    try {
      String pem = toPem("CERTIFICATE", certificate.getEncoded());
      Files.writeString(path, pem);
    } catch (CertificateEncodingException e) {
      throw new IOException("Failed to encode certificate", e);
    }
  }

  static String toPem(String type, byte[] encoded) {
    String base64 =
        Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(encoded);
    return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
  }

  private static String certificateBase64(X509Certificate certificate) {
    try {
      return Base64.getEncoder().encodeToString(certificate.getEncoded());
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to encode certificate", e);
    }
  }

  private static boolean probeForBouncyCastle() {
    try {
      Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
      return true;
    } catch (ClassNotFoundException ignored) {
      return false;
    }
  }
}
