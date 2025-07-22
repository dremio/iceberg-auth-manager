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

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PolarisTestEnvironment.class)
public class OAuth2AgentPolarisLT extends OAuth2AgentLTBase {

  @Test
  void backgroundRefreshAndSleep(Builder envBuilder1, Builder envBuilder2)
      throws ExecutionException, InterruptedException {
    run(envBuilder1, envBuilder2);
  }

  @Override
  protected void authenticate(OAuth2Agent agent) {
    AccessToken accessToken = agent.authenticate();
    DecodedJWT jwt = JWT.decode(accessToken.getPayload());
    assertThat(jwt).isNotNull();
    assertThat(jwt.getClaim("active").asBoolean()).isTrue();
    assertThat(jwt.getClaim("scope").asString()).contains("PRINCIPAL_ROLE:ALL");
  }
}
