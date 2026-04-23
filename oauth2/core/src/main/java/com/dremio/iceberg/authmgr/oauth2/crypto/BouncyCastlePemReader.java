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
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

final class BouncyCastlePemReader implements PemReader {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  BouncyCastlePemReader() {}

  /**
   * Reads a private key from a PEM file. Supported key formats:
   *
   * <ul>
   *   <li>RSA or EC PKCS#8 (BEGIN PRIVATE KEY)
   *   <li>RSA PKCS#1 (BEGIN RSA PRIVATE KEY)
   *   <li>EC SEC 1 (BEGIN EC PRIVATE KEY)
   * </ul>
   *
   * <p>Only unencrypted keys are supported.
   *
   * @param file the path to the PEM file containing the private key
   * @return the RSA private key
   * @throws IllegalArgumentException if the file cannot be read, parsed, or doesn't contain a valid
   *     RSA private key
   */
  @Override
  public PrivateKey readPrivateKey(Path file) {
    try (Reader reader = Files.newBufferedReader(file);
        PEMParser pemParser = new PEMParser(reader)) {
      Object pemObject;
      while ((pemObject = pemParser.readObject()) != null) {
        PrivateKey privateKey = extractPrivateKey(pemObject);
        if (privateKey != null) {
          return privateKey;
        }
      }
      throw new IllegalArgumentException("No private key found in file: " + file);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + file, e);
    }
  }

  /**
   * Reads a public key from a PEM file. Supported key formats:
   *
   * <ul>
   *   <li>RSA or EC X.509 SubjectPublicKeyInfo (BEGIN PUBLIC KEY)
   * </ul>
   *
   * @param file the path to the PEM file containing the public key
   * @return the public key
   * @throws IllegalArgumentException if the file cannot be read or parsed, or doesn't contain a
   *     valid public key
   */
  @Override
  public PublicKey readPublicKey(Path file) {
    try (Reader reader = Files.newBufferedReader(file);
        PEMParser pemParser = new PEMParser(reader)) {
      Object pemObject;
      while ((pemObject = pemParser.readObject()) != null) {
        PublicKey publicKey = extractPublicKey(pemObject);
        if (publicKey != null) {
          return publicKey;
        }
      }
      throw new IllegalArgumentException("No public key found in file: " + file);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + file, e);
    }
  }

  @Override
  public PublicKey derivePublicKey(PrivateKey privateKey) {
    if (privateKey instanceof RSAPrivateCrtKey) {
      return JcaPemReader.deriveRsaPublicKey((RSAPrivateCrtKey) privateKey);
    }
    if (privateKey instanceof ECPrivateKey) {
      return deriveEcPublicKey((ECPrivateKey) privateKey);
    }
    throw new IllegalArgumentException(
        "Unsupported private key type: " + privateKey.getClass().getName());
  }

  /** Derives the public key using BouncyCastle EC arithmetic. */
  private static PublicKey deriveEcPublicKey(ECPrivateKey ecPrivateKey) {
    java.security.spec.ECParameterSpec jcaSpec = ecPrivateKey.getParams();
    org.bouncycastle.math.ec.ECPoint bcG = getEcPoint(jcaSpec);
    org.bouncycastle.math.ec.ECPoint bcQ = bcG.multiply(ecPrivateKey.getS()).normalize();
    ECPoint jcaQ =
        new ECPoint(bcQ.getAffineXCoord().toBigInteger(), bcQ.getAffineYCoord().toBigInteger());
    try {
      return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(jcaQ, jcaSpec));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Failed to derive EC public key", e);
    }
  }

  private static org.bouncycastle.math.ec.ECPoint getEcPoint(ECParameterSpec jcaSpec) {
    EllipticCurve jcaCurve = jcaSpec.getCurve();
    if (!(jcaCurve.getField() instanceof ECFieldFp)) {
      throw new IllegalArgumentException(
          "Only prime-field EC curves are supported for public key derivation");
    }
    BigInteger p = ((ECFieldFp) jcaCurve.getField()).getP();
    BigInteger a = jcaCurve.getA();
    BigInteger b = jcaCurve.getB();
    BigInteger n = jcaSpec.getOrder();
    BigInteger h = BigInteger.valueOf(jcaSpec.getCofactor());
    ECCurve bcCurve = new ECCurve.Fp(p, a, b, n, h);
    ECPoint jcaG = jcaSpec.getGenerator();
    return bcCurve.createPoint(jcaG.getAffineX(), jcaG.getAffineY());
  }

  private static PublicKey extractPublicKey(Object pemObject) throws PEMException {
    // Nimbus JOSE JWT uses "EC" as the algorithm name for EC keys,
    // but BouncyCastle uses "ECDSA"; normalize to "EC" for compatibility.
    JcaPEMKeyConverter converter =
        new JcaPEMKeyConverter().setAlgorithmMapping(X9ObjectIdentifiers.id_ecPublicKey, "EC");
    if (pemObject instanceof SubjectPublicKeyInfo) {
      return converter.getPublicKey((SubjectPublicKeyInfo) pemObject);
    }
    return null;
  }

  private static PrivateKey extractPrivateKey(Object pemObject) throws PEMException {
    // Nimbus JOSE JWT uses "EC" as the algorithm name for EC keys,
    // but BouncyCastle uses "ECDSA"; normalize to "EC" for compatibility.
    JcaPEMKeyConverter converter =
        new JcaPEMKeyConverter().setAlgorithmMapping(X9ObjectIdentifiers.id_ecPublicKey, "EC");
    if (pemObject instanceof PEMKeyPair) {
      // Handle PKCS#1 format (BEGIN RSA PRIVATE KEY) or SEC 1 (BEGIN EC PRIVATE KEY)
      return converter.getPrivateKey(((PEMKeyPair) pemObject).getPrivateKeyInfo());
    } else if (pemObject instanceof PrivateKeyInfo) {
      // Handle PKCS#8 format (BEGIN PRIVATE KEY)
      return converter.getPrivateKey((PrivateKeyInfo) pemObject);
    }
    return null;
  }
}
