/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.dremio.iceberg.authmgr.oauth2.agent;

import static com.dremio.iceberg.authmgr.oauth2.grant.GrantType.AUTHORIZATION_CODE;
import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.KeycloakExtension;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(KeycloakExtension.class)
public class OAuth2AgentKeycloakLongIT extends OAuth2AgentLongITBase {

  @Test
  void backgroundRefreshAndSleep(Builder envBuilder1, Builder envBuilder2) {
    run(envBuilder1, envBuilder2.grantType(AUTHORIZATION_CODE).impersonationEnabled(true));
  }

  @Override
  protected void authenticate(OAuth2Agent agent) {
    AccessToken accessToken = agent.authenticate();
    DecodedJWT jwt = JWT.decode(accessToken.getPayload());
    assertThat(jwt).isNotNull();
    assertThat(jwt.getClaim("azp").asString()).isEqualTo(TestConstants.CLIENT_ID1);
    assertThat(jwt.getClaim("scope").asString()).contains(TestConstants.SCOPE1);
  }
}
