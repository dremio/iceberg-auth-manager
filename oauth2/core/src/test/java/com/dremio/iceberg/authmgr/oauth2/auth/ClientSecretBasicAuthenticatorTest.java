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
package com.dremio.iceberg.authmgr.oauth2.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ClientSecretBasicAuthenticatorTest {

  @Test
  void authenticate() {
    ClientSecretBasicAuthenticator authenticator =
        ImmutableClientSecretBasicAuthenticator.builder()
            .clientId(TestConstants.CLIENT_ID1)
            .clientSecret(Secret.of(TestConstants.CLIENT_SECRET1))
            .build();
    assertThat(authenticator.getClientId()).isEqualTo(TestConstants.CLIENT_ID1);
    assertThat(authenticator.getClientSecret()).isEqualTo(Secret.of(TestConstants.CLIENT_SECRET1));
    Map<String, String> headers = new HashMap<>();
    authenticator.authenticate(ClientCredentialsTokenRequest.builder(), headers, null);
    assertThat(headers)
        .containsEntry("Authorization", "Basic " + TestConstants.CLIENT_CREDENTIALS1_BASE_64);
  }
}
