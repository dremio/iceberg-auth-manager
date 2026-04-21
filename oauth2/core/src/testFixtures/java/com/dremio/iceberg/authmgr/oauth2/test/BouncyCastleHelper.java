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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/**
 * BouncyCastle-dependent helpers for {@link TestCertificates}.
 *
 * <p>This class is deliberately in its own file so that its BouncyCastle imports do not pollute
 * {@code TestCertificates}, which must be loadable without BouncyCastle on the classpath.
 */
final class BouncyCastleHelper {

  private BouncyCastleHelper() {}

  static void writePkcs1Pem(PrivateKey key, Path path) throws IOException {
    PrivateKeyInfo pkcs8Info = PrivateKeyInfo.getInstance(key.getEncoded());
    byte[] pkcs1Bytes = pkcs8Info.parsePrivateKey().toASN1Primitive().getEncoded(ASN1Encoding.DER);
    String pem = TestCertificates.toPem("RSA PRIVATE KEY", pkcs1Bytes);
    Files.writeString(path, pem);
  }

  static void writeEcPrivateKeyPem(PrivateKey key, Path path) throws IOException {
    PrivateKeyInfo pkcs8Info = PrivateKeyInfo.getInstance(key.getEncoded());
    java.security.interfaces.ECPrivateKey jcaKey = (java.security.interfaces.ECPrivateKey) key;
    org.bouncycastle.asn1.sec.ECPrivateKey ecPrivateKey =
        new org.bouncycastle.asn1.sec.ECPrivateKey(
            jcaKey.getParams().getOrder().bitLength(),
            jcaKey.getS(),
            pkcs8Info.getPrivateKeyAlgorithm().getParameters());
    byte[] ecBytes = ecPrivateKey.getEncoded(ASN1Encoding.DER);
    String pem = TestCertificates.toPem("EC PRIVATE KEY", ecBytes);
    Files.writeString(path, pem);
  }
}
