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

public final class ClientAuthenticatorFactory {

  public static ClientAuthenticator createAuthenticator(OAuth2AgentSpec spec) {
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
        default:
          throw new IllegalArgumentException("Unsupported client authentication method: " + method);
      }
    }
  }

  public static ClientAuthenticator createImpersonatingAuthenticator(OAuth2AgentSpec spec) {
    ClientAuthentication method = spec.getImpersonationConfig().getClientAuthentication();
    switch (method) {
      case NONE:
        return ImmutablePublicClientAuthenticator.builder()
            .clientId(spec.getImpersonationConfig().getClientId().orElseThrow())
            .build();
      case CLIENT_SECRET_BASIC:
        return ImmutableClientSecretBasicAuthenticator.builder()
            .clientId(spec.getImpersonationConfig().getClientId().orElseThrow())
            .clientSecret(spec.getImpersonationConfig().getClientSecret().orElseThrow())
            .build();
      case CLIENT_SECRET_POST:
        return ImmutableClientSecretPostAuthenticator.builder()
            .clientId(spec.getImpersonationConfig().getClientId().orElseThrow())
            .clientSecret(spec.getImpersonationConfig().getClientSecret().orElseThrow())
            .build();
      default:
        throw new IllegalArgumentException("Unsupported client authentication method: " + method);
    }
  }
}
