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

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import java.net.URI;

public final class ClientAuthenticatorFactory {

  public static ClientAuthenticator createAuthenticator(OAuth2AgentSpec spec, URI tokenEndpoint) {
    if (spec.getBasicConfig().getDialect() == Dialect.ICEBERG_REST
        || spec.getBasicConfig().getToken().isPresent()) {
      return ImmutableIcebergClientAuthenticator.builder()
          .clientId(spec.getBasicConfig().getClientId())
          .clientSecret(spec.getBasicConfig().getClientSecret())
          .build();
    } else {
      ClientAuthentication method = spec.getBasicConfig().getClientAuthentication();
      switch (method) {
        case NONE:
          return ImmutablePublicClientAuthenticator.builder()
              .clientId(spec.getBasicConfig().getClientId().orElseThrow())
              .build();
        case CLIENT_SECRET_BASIC:
          return ImmutableClientSecretBasicAuthenticator.builder()
              .clientId(spec.getBasicConfig().getClientId().orElseThrow())
              .clientSecret(spec.getBasicConfig().getClientSecret().orElseThrow())
              .build();
        case CLIENT_SECRET_POST:
          return ImmutableClientSecretPostAuthenticator.builder()
              .clientId(spec.getBasicConfig().getClientId().orElseThrow())
              .clientSecret(spec.getBasicConfig().getClientSecret().orElseThrow())
              .build();
        case CLIENT_SECRET_JWT:
          return ImmutableClientSecretJwtAuthenticator.builder()
              .clientId(spec.getBasicConfig().getClientId().orElseThrow())
              .clientSecret(spec.getBasicConfig().getClientSecret().orElseThrow())
              .clientAssertionConfig(spec.getClientAssertionConfig())
              .tokenEndpoint(tokenEndpoint)
              .clock(spec.getRuntimeConfig().getClock())
              .build();
        case PRIVATE_KEY_JWT:
          return ImmutablePrivateKeyJwtClientAuthenticator.builder()
              .clientId(spec.getBasicConfig().getClientId().orElseThrow())
              .clientAssertionConfig(spec.getClientAssertionConfig())
              .tokenEndpoint(tokenEndpoint)
              .clock(spec.getRuntimeConfig().getClock())
              .build();
        default:
          throw new IllegalArgumentException("Unsupported client authentication method: " + method);
      }
    }
  }
}
