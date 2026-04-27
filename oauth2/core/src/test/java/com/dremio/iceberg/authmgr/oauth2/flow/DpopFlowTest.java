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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestServer;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.mockserver.model.HttpRequest;

class DpopFlowTest {

  @CartesianTest
  void testDpop(
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @EnumLike GrantType initialGrantType)
      throws Exception {

    assumeTrue(
        authenticationMethod != ClientAuthenticationMethod.NONE
            || initialGrantType != GrantType.CLIENT_CREDENTIALS);

    try (TestEnvironment env =
            TestEnvironment.builder()
                .clientAuthenticationMethod(authenticationMethod)
                .grantType(initialGrantType)
                .dpopEnabled(true)
                .dpopAlgorithm(JWSAlgorithm.ES256)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {

      Flow flow = flowFactory.createInitialFlow();
      flow.fetchNewTokens().toCompletableFuture().get();

      HttpRequest[] recorded =
          TestServer.getInstance()
              .retrieveRecordedRequests(
                  HttpRequest.request().withPath(env.getTokenEndpoint().getPath()));
      assertThat(recorded).hasSizeGreaterThanOrEqualTo(1);

      String dpopHeader = recorded[0].getFirstHeader("DPoP");
      assertThat(dpopHeader).isNotBlank();

      SignedJWT proof = SignedJWT.parse(dpopHeader);
      assertThat(proof.getHeader().getType().getType()).isEqualTo("dpop+jwt");

      JWK jwk = proof.getHeader().getJWK();
      assertThat(jwk).isNotNull();
      assertThat(jwk.isPrivate()).isFalse();

      JWTClaimsSet claims = proof.getJWTClaimsSet();
      assertThat(claims.getJWTID()).isNotBlank();
      assertThat(claims.getStringClaim("htm")).isEqualTo("POST");
      assertThat(claims.getStringClaim("htu")).isEqualTo(env.getTokenEndpoint().toString());
      assertThat(claims.getIssueTime()).isEqualTo(TestConstants.NOW);

      // Token endpoint requests don't present an access token: no ath claim.
      assertThat(claims.getStringClaim("ath")).isNull();

      JWSVerifier verifier = new ECDSAVerifier((ECKey) jwk);
      assertThat(proof.verify(verifier)).isTrue();
    }
  }

  @Test
  void testDpopNonceChallengeTriggersRetryWithNonce() throws Exception {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .dpopEnabled(true)
                .requireDpopNonce(true)
                .dpopAlgorithm(JWSAlgorithm.ES256)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {

      Flow flow = flowFactory.createInitialFlow();
      flow.fetchNewTokens().toCompletableFuture().get();

      HttpRequest[] recorded =
          TestServer.getInstance()
              .retrieveRecordedRequests(
                  HttpRequest.request().withPath(env.getTokenEndpoint().getPath()));
      assertThat(recorded).hasSize(2);

      // First proof: no nonce claim (cache is empty at this point).
      JWTClaimsSet firstClaims =
          SignedJWT.parse(recorded[0].getFirstHeader("DPoP")).getJWTClaimsSet();
      assertThat(firstClaims.getStringClaim("nonce")).isNull();

      // Second proof: nonce claim equals what the server supplied.
      JWTClaimsSet secondClaims =
          SignedJWT.parse(recorded[1].getFirstHeader("DPoP")).getJWTClaimsSet();
      assertThat(secondClaims.getStringClaim("nonce")).isEqualTo(env.getDpopNonce());

      // Second proof must also be a distinct JWT, not a replay.
      assertThat(secondClaims.getJWTID()).isNotEqualTo(firstClaims.getJWTID());
    }
  }
}
