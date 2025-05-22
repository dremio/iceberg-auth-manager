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

import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;

public class FlowFactory {

  public static Flow forInitialTokenFetch(GrantType grantType, FlowContext context) {
    switch (grantType) {
      case CLIENT_CREDENTIALS:
        return new ClientCredentialsFlow(context);
      case PASSWORD:
        return new PasswordFlow(context);
      case AUTHORIZATION_CODE:
        return new AuthorizationCodeFlow(context);
      case DEVICE_CODE:
        return new DeviceCodeFlow(context);
      case TOKEN_EXCHANGE:
        return new TokenExchangeFlow(context);
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid grant type for initial token fetch: " + grantType);
    }
  }

  public static Flow forTokenRefresh(Dialect dialect, FlowContext context) {
    switch (dialect) {
      case STANDARD:
        return new RefreshTokenFlow(context);
      case ICEBERG_REST:
        return new IcebergRefreshTokenFlow(context);
      default:
        throw new IllegalArgumentException("Unknown or invalid dialect: " + dialect);
    }
  }

  public static Flow forImpersonation(FlowContext context) {
    return new ImpersonatingTokenExchangeFlow(context);
  }
}
