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
package com.dremio.iceberg.authmgr.oauth2.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.dremio.iceberg.authmgr.oauth2.test.junit.PolarisExtension;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.text.ParseException;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.cartesian.CartesianTest;

/** Tests for {@link OAuth2Agent} against an Apache Polaris server. */
@ExtendWith(PolarisExtension.class)
public class OAuth2AgentPolarisIT {

  @CartesianTest
  void clientCredentials(
      @EnumLike(includes = {"client_secret_basic", "client_secret_post"})
          ClientAuthenticationMethod clientAuthenticationMethod,
      Builder envBuilder)
      throws Exception {
    try (TestEnvironment env =
            envBuilder.clientAuthenticationMethod(clientAuthenticationMethod).build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult tokens = agent.authenticateInternal();
      introspectToken(tokens.getTokens().getAccessToken());
      assertThat(tokens.getTokens().getRefreshToken()).isNull();
    }
  }

  private void introspectToken(AccessToken accessToken) throws ParseException {
    assertThat(accessToken).isNotNull();
    JWT jwt = JWTParser.parse(accessToken.getValue());
    assertThat(jwt).isNotNull();
    assertThat(jwt.getJWTClaimsSet().getBooleanClaim("active")).isTrue();
    assertThat(jwt.getJWTClaimsSet().getStringClaim("scope")).isEqualTo("PRINCIPAL_ROLE:ALL");
  }
}
