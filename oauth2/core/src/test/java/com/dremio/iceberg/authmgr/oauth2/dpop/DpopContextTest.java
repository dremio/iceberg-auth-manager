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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.dremio.iceberg.authmgr.oauth2.config.DpopConfig;
import com.dremio.iceberg.authmgr.oauth2.test.TestCertificates;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DpopContextTest {

  private static final URI TOKEN_ENDPOINT = URI.create("https://as.example.com/token");

  @ParameterizedTest
  @MethodSource("ephemeralAlgorithms")
  void testEphemeral(JWSAlgorithm algorithm) throws Exception {
    DpopContext ctx =
        DpopContext.create(
            loadConfig(
                Map.of(
                    DpopConfig.PREFIX + '.' + DpopConfig.ENABLED,
                    "true",
                    DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM,
                    algorithm.getName())),
            Clock.systemUTC());
    assertSignAndVerify(ctx);
  }

  static Stream<Arguments> ephemeralAlgorithms() {
    return Stream.of(
        Arguments.of(JWSAlgorithm.ES256),
        Arguments.of(JWSAlgorithm.ES384),
        Arguments.of(JWSAlgorithm.ES512),
        Arguments.of(JWSAlgorithm.RS256),
        Arguments.of(JWSAlgorithm.PS256));
  }

  @Test
  void testLoadRsaPkcs8() throws Exception {
    Path pem = TestCertificates.instance().getRsaPrivateKeyPkcs8Pem();
    DpopContext ctx =
        DpopContext.create(
            loadConfig(
                Map.of(
                    DpopConfig.PREFIX + '.' + DpopConfig.ENABLED, "true",
                    DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM, "RS256",
                    DpopConfig.PREFIX + '.' + DpopConfig.PRIVATE_KEY, pem.toString())),
            Clock.systemUTC());
    assertSignAndVerify(ctx);
  }

  @Test
  void testLoadEcPkcs8() throws Exception {
    Path pem = TestCertificates.instance().getEcdsaPrivateKeyPkcs8Pem();
    DpopContext ctx =
        DpopContext.create(
            loadConfig(
                Map.of(
                    DpopConfig.PREFIX + '.' + DpopConfig.ENABLED, "true",
                    DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM, "ES256",
                    DpopConfig.PREFIX + '.' + DpopConfig.PRIVATE_KEY, pem.toString())),
            Clock.systemUTC());
    assertSignAndVerify(ctx);
  }

  @Test
  void testLoadEcPkcs8WithExplicitPublicKey() throws Exception {
    Path privPem = TestCertificates.instance().getEcdsaPrivateKeyPkcs8Pem();
    Path pubPem = TestCertificates.instance().getEcdsaPublicKeyPem();
    DpopContext ctx =
        DpopContext.create(
            loadConfig(
                Map.of(
                    DpopConfig.PREFIX + '.' + DpopConfig.ENABLED,
                    "true",
                    DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM,
                    "ES256",
                    DpopConfig.PREFIX + '.' + DpopConfig.PRIVATE_KEY,
                    privPem.toString(),
                    DpopConfig.PREFIX + '.' + DpopConfig.PUBLIC_KEY,
                    pubPem.toString())),
            Clock.systemUTC());
    assertSignAndVerify(ctx);
  }

  @Test
  void testAlgorithmKeyMismatch() {
    Path rsaPem = TestCertificates.instance().getRsaPrivateKeyPkcs8Pem();
    DpopConfig config =
        loadConfig(
            Map.of(
                DpopConfig.PREFIX + '.' + DpopConfig.ENABLED, "true",
                DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM, "ES256",
                DpopConfig.PREFIX + '.' + DpopConfig.PRIVATE_KEY, rsaPem.toString()));

    assertThatThrownBy(() -> DpopContext.create(config, Clock.systemUTC()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("not compatible with algorithm ES256");
  }

  @Test
  void testCopySharesKeyButIsolatesNonceCache() {
    DpopContext original = newContext();
    Nonce n1 = new Nonce("n-1");
    Nonce n2 = new Nonce("n-2");
    original.getNonceCache().put(DpopScope.AS, n1);

    DpopContext copy = original.copy();

    // immutable state shared by reference
    assertThat(copy.getProofFactory()).isSameAs(original.getProofFactory());

    // nonce cache seeded, but independent
    assertThat(copy.getNonceCache()).isNotSameAs(original.getNonceCache());
    assertThat(copy.getNonceCache().get(DpopScope.AS)).hasValue(n1);

    copy.getNonceCache().put(DpopScope.AS, n2);
    assertThat(original.getNonceCache().get(DpopScope.AS)).hasValue(n1);
    assertThat(copy.getNonceCache().get(DpopScope.AS)).hasValue(n2);
  }

  @Test
  void testCreateProofHeaderAndClaims() throws Exception {
    DpopContext ctx = newContext();

    SignedJWT proof = ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, null);

    assertThat(proof.getHeader().getType().getType()).isEqualTo("dpop+jwt");
    JWK jwk = proof.getHeader().getJWK();
    assertThat(jwk).isNotNull();
    assertThat(jwk.isPrivate()).isFalse();

    JWTClaimsSet claims = proof.getJWTClaimsSet();
    assertThat(claims.getJWTID()).isNotBlank();
    assertThat(claims.getStringClaim("htm")).isEqualTo("POST");
    assertThat(claims.getStringClaim("htu")).isEqualTo(TOKEN_ENDPOINT.toString());
    assertThat(claims.getIssueTime()).isNotNull();
    assertThat(claims.getStringClaim("ath")).isNull();
    assertThat(claims.getStringClaim("nonce")).isNull();

    JWSVerifier verifier = new ECDSAVerifier((ECKey) jwk);
    assertThat(proof.verify(verifier)).isTrue();
  }

  @Test
  void testCreateProofUsesInjectedClock() throws Exception {
    DpopContext ctx =
        DpopContext.create(enabledEcConfig(), Clock.fixed(TestConstants.NOW, ZoneOffset.UTC));

    SignedJWT proof = ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, null);

    assertThat(proof.getJWTClaimsSet().getIssueTime().toInstant()).isEqualTo(TestConstants.NOW);
  }

  @Test
  void testCreateProofNormalizesHtu() throws Exception {
    DpopContext ctx = newContext();

    SignedJWT proof =
        ctx.createProof(
            DpopScope.AS, "POST", URI.create("https://as.example.com/token?x=1#f"), null);

    assertThat(proof.getJWTClaimsSet().getStringClaim("htu"))
        .isEqualTo("https://as.example.com/token");
  }

  @Test
  void testCreateProofIncludesCachedAsNonce() throws Exception {
    DpopContext ctx = newContext();
    ctx.getNonceCache().put(DpopScope.AS, new Nonce("n-abc"));

    SignedJWT proof = ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, null);

    assertThat(proof.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("n-abc");
  }

  @Test
  void testCreateProofForRsDoesNotUseAsNonce() throws Exception {
    // Same-origin deployment: AS and RS behind the same proxy (http://host/). An AS-issued nonce
    // must not leak into an RS proof.
    DpopContext ctx = newContext();
    ctx.getNonceCache().put(DpopScope.AS, new Nonce("n-as"));

    SignedJWT proof =
        ctx.createProof(
            DpopScope.RS,
            "GET",
            URI.create("https://as.example.com/resource"),
            new DPoPAccessToken("rs-token"));

    assertThat(proof.getJWTClaimsSet().getStringClaim("nonce")).isNull();
  }

  @Test
  void testCreateProofRejectsMismatchedScopeAndAccessToken() {
    DpopContext ctx = newContext();

    assertThatThrownBy(() -> ctx.createProof(DpopScope.RS, "GET", TOKEN_ENDPOINT, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("resource-server request must carry an access token");

    assertThatThrownBy(
            () -> ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, new DPoPAccessToken("x")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("token-endpoint request must not carry an access token");
  }

  @Test
  void testCreateProofNormalizesHtmToUppercase() throws Exception {
    DpopContext ctx = newContext();

    SignedJWT proof = ctx.createProof(DpopScope.AS, "get", TOKEN_ENDPOINT, null);

    assertThat(proof.getJWTClaimsSet().getStringClaim("htm")).isEqualTo("GET");
  }

  @Test
  void testCreateProofJtiUniquePerCall() throws Exception {
    DpopContext ctx = newContext();

    String jti1 =
        ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, null).getJWTClaimsSet().getJWTID();
    String jti2 =
        ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, null).getJWTClaimsSet().getJWTID();

    assertThat(jti1).isNotEqualTo(jti2);
  }

  @Test
  void testCreateProofIncludesAthForAccessToken() throws Exception {
    DpopContext ctx = newContext();
    String tokenValue = "access-token-xyz";
    DPoPAccessToken accessToken = new DPoPAccessToken(tokenValue);

    SignedJWT proof =
        ctx.createProof(
            DpopScope.RS, "GET", URI.create("https://rs.example.com/warehouses"), accessToken);

    JWTClaimsSet claims = proof.getJWTClaimsSet();
    byte[] expectedHash =
        MessageDigest.getInstance("SHA-256").digest(tokenValue.getBytes(StandardCharsets.US_ASCII));
    assertThat(claims.getStringClaim("ath")).isEqualTo(Base64URL.encode(expectedHash).toString());
    assertThat(claims.getStringClaim("htm")).isEqualTo("GET");
    assertThat(claims.getStringClaim("htu")).isEqualTo("https://rs.example.com/warehouses");
  }

  @Test
  void testCaptureNonceStoresInCacheByScope() {
    DpopContext ctx = newContext();

    ctx.captureNonce(DpopScope.AS, new Nonce("n-123"));

    assertThat(ctx.getNonceCache().get(DpopScope.AS)).hasValue(new Nonce("n-123"));
    assertThat(ctx.getNonceCache().get(DpopScope.RS)).isEmpty();
  }

  private static DpopContext newContext() {
    return DpopContext.create(enabledEcConfig(), Clock.systemUTC());
  }

  private static DpopConfig enabledEcConfig() {
    return loadConfig(
        Map.of(
            DpopConfig.PREFIX + '.' + DpopConfig.ENABLED, "true",
            DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM, "ES256"));
  }

  private static DpopConfig loadConfig(Map<String, String> properties) {
    return new SmallRyeConfigBuilder()
        .withMapping(DpopConfig.class, DpopConfig.PREFIX)
        .withSources(new MapBackedConfigSource("test", properties, 1000) {})
        .build()
        .getConfigMapping(DpopConfig.class, DpopConfig.PREFIX);
  }

  private static void assertSignAndVerify(DpopContext ctx) throws Exception {
    SignedJWT proof = ctx.createProof(DpopScope.AS, "POST", TOKEN_ENDPOINT, null);
    JWK jwk = proof.getHeader().getJWK();
    JWSVerifier verifier =
        jwk instanceof ECKey ? new ECDSAVerifier((ECKey) jwk) : new RSASSAVerifier((RSAKey) jwk);
    assertThat(proof.verify(verifier)).isTrue();
  }
}
