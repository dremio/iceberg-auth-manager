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
package com.dremio.iceberg.authmgr.oauth2.dpop;

import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.DpopConfig;
import com.dremio.iceberg.authmgr.oauth2.crypto.PemReader;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Per-agent bundle holding the DPoP key material, proof factory, and nonce cache.
 *
 * <p>The key (and therefore the proof factory over it) is immutable for the lifetime of the agent;
 * this is required by RFC 9449 §5, which binds issued refresh tokens to the public key used at
 * issuance. Presenting a refresh token later requires a proof signed by the same key.
 *
 * <p>When an agent is copied (see {@link #copy()}), the key and proof factory are shared by
 * reference. The nonce cache is deep-copied so each agent has independent mutable state.
 */
@AuthManagerImmutable
public abstract class DpopContext {

  private static final Logger LOGGER = LoggerFactory.getLogger(DpopContext.class);

  private static final int RSA_KEY_SIZE_BITS = 2048;

  public static DpopContext create(DpopConfig config, Clock clock) {
    JWSAlgorithm algorithm = config.getAlgorithm();
    KeyPair keyPair =
        config
            .getPrivateKey()
            .map(path -> loadKeyPair(path, config.getPublicKey().orElse(null), algorithm))
            .orElseGet(() -> generateKeyPair(algorithm));
    JWK jwk = toJwk(algorithm, keyPair.getPublic(), keyPair.getPrivate());
    return ImmutableDpopContext.builder().jwk(jwk).algorithm(algorithm).clock(clock).build();
  }

  protected abstract JWK getJwk();

  protected abstract JWSAlgorithm getAlgorithm();

  protected abstract Clock getClock();

  @Value.Default
  protected DPoPProofFactory getProofFactory() {
    try {
      return new DefaultDPoPProofFactory(getJwk(), getAlgorithm());
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to initialize DPoP proof factory", e);
    }
  }

  @Value.Default
  protected DpopNonceCache getNonceCache() {
    return new DpopNonceCache();
  }

  /**
   * Returns a new context that shares the key and proof factory with this one but has an
   * independent nonce cache seeded with this cache's current entries.
   */
  public DpopContext copy() {
    return ImmutableDpopContext.builder().from(this).nonceCache(getNonceCache().copy()).build();
  }

  /**
   * Builds a fresh DPoP proof JWT for a request, using the origin's currently cached nonce, if any.
   * When {@code accessToken} is non-null, the proof includes an {@code ath} claim binding the proof
   * to that access token (RFC 9449 §7).
   *
   * <p>The {@code htu} claim is normalized per RFC 9449 §4.2 (scheme + authority + path, no query
   * or fragment).
   */
  public SignedJWT createProof(
      DpopScope scope, String method, URI uri, @Nullable AccessToken accessToken) {
    // RFC 9449 §7 requires proofs for resource-server requests to bind the access token via `ath`;
    // conversely, token-endpoint requests have no access token yet (§4.2).
    if (scope == DpopScope.RS && accessToken == null) {
      throw new IllegalArgumentException(
          "DPoP proof for a resource-server request must carry an access token");
    }
    if (scope == DpopScope.AS && accessToken != null) {
      throw new IllegalArgumentException(
          "DPoP proof for a token-endpoint request must not carry an access token");
    }
    // RFC 9449 §4.2 / RFC 9110 §9.1: standardized HTTP method tokens are all-uppercase
    String htm = method.toUpperCase(Locale.ROOT);
    URI htu = normalizeHtu(uri);
    Nonce nonce = getNonceCache().get(scope).orElse(null);
    Date iat = Date.from(getClock().instant());
    try {
      return getProofFactory().createDPoPJWT(new JWTID(), htm, htu, iat, accessToken, nonce);
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to sign DPoP proof", e);
    }
  }

  public void captureNonce(DpopScope scope, Nonce nonce) {
    getNonceCache().put(scope, nonce);
  }

  private static KeyPair generateKeyPair(JWSAlgorithm algorithm) {
    try {
      Curve curve = ConfigUtils.SUPPORTED_DPOP_EC_ALGORITHMS.get(algorithm);
      if (curve != null) {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve.getStdName()));
        return generator.generateKeyPair();
      }
      if (ConfigUtils.SUPPORTED_DPOP_RSA_ALGORITHMS.contains(algorithm)) {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_KEY_SIZE_BITS);
        return generator.generateKeyPair();
      }
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new IllegalStateException(
          "Failed to generate DPoP keypair for algorithm " + algorithm, e);
    }
    throw unsupportedAlgorithm(algorithm);
  }

  private static KeyPair loadKeyPair(
      Path privateKeyPath, @Nullable Path publicKeyPath, JWSAlgorithm algorithm) {
    PemReader reader = PemReader.getInstance();
    PrivateKey privateKey = reader.readPrivateKey(privateKeyPath);
    checkKeyMatchesAlgorithm(privateKey, algorithm);
    PublicKey publicKey;
    if (publicKeyPath != null) {
      publicKey = reader.readPublicKey(publicKeyPath);
      checkKeyMatchesAlgorithm(publicKey, algorithm);
    } else {
      try {
        publicKey = reader.derivePublicKey(privateKey);
      } catch (IllegalStateException e) {
        throw new IllegalStateException(
            "DPoP: could not derive public key from private key. "
                + "Either add BouncyCastle to the runtime classpath, or set "
                + DpopConfig.PREFIX
                + '.'
                + DpopConfig.PUBLIC_KEY
                + " to point at the public key PEM file.",
            e);
      }
    }
    return new KeyPair(publicKey, privateKey);
  }

  private static JWK toJwk(JWSAlgorithm algorithm, PublicKey publicKey, PrivateKey privateKey) {
    Curve curve = ConfigUtils.SUPPORTED_DPOP_EC_ALGORITHMS.get(algorithm);
    if (curve != null) {
      return new ECKey.Builder(curve, (ECPublicKey) publicKey)
          .privateKey((ECPrivateKey) privateKey)
          .build();
    }
    if (ConfigUtils.SUPPORTED_DPOP_RSA_ALGORITHMS.contains(algorithm)) {
      return new RSAKey.Builder((RSAPublicKey) publicKey)
          .privateKey((RSAPrivateKey) privateKey)
          .build();
    }
    throw unsupportedAlgorithm(algorithm);
  }

  private static void checkKeyMatchesAlgorithm(Key key, JWSAlgorithm algorithm) {
    boolean rsaKey = key instanceof java.security.interfaces.RSAKey;
    boolean ecKey = key instanceof java.security.interfaces.ECKey;
    boolean rsaAlg = ConfigUtils.SUPPORTED_DPOP_RSA_ALGORITHMS.contains(algorithm);
    boolean ecAlg = ConfigUtils.SUPPORTED_DPOP_EC_ALGORITHMS.containsKey(algorithm);
    if (!((rsaKey && rsaAlg) || (ecKey && ecAlg))) {
      throw new IllegalArgumentException(
          String.format(
              "DPoP: loaded %s key type %s is not compatible with algorithm %s",
              key instanceof PrivateKey ? "private" : "public",
              key.getClass().getSimpleName(),
              algorithm.getName()));
    }
  }

  private static IllegalArgumentException unsupportedAlgorithm(JWSAlgorithm algorithm) {
    return new IllegalArgumentException(
        "DPoP: unsupported algorithm '"
            + algorithm.getName()
            + "'; supported: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512");
  }

  /**
   * Strips query and fragment from the URI per RFC 9449 §4.2 so the resulting {@code htu} claim is
   * deterministic regardless of how the caller built the URI. Defensive: Nimbus's proof factory may
   * or may not normalize; doing it here guarantees RFC-compliant output.
   */
  private static URI normalizeHtu(URI uri) {
    if (uri.getQuery() == null && uri.getFragment() == null) {
      return uri;
    }
    try {
      return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), null, null);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid htu: " + uri, e);
    }
  }
}
