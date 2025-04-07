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

import java.util.Locale;

/**
 * Client authentication methods for OAuth2. These methods are used to authenticate the client
 * application to the authorization server when requesting an access token.
 *
 * <p>The client authentication methods specified here are based on the client authentication
 * methods defined in <a
 * href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID Connect
 * Core 1.0</a>.
 *
 * <p>See also <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1">RFC 6749,
 * Section 2.3.1</a> and <a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2">RFC
 * 7523, Section 2.2</a> for more information.
 */
public enum ClientAuthentication {

  // Public clients

  /**
   * The Client does not authenticate itself at the Token Endpoint, because it is a Public Client
   * with no Client Secret or other authentication mechanism.
   */
  NONE("none"),

  // From OAuth 2.0 (RFC 6749)

  /**
   * Clients that have received a client_secret value authenticate using the HTTP Basic
   * authentication scheme.
   */
  CLIENT_SECRET_BASIC("client_secret_basic"),

  /**
   * Clients that have received a client_secret value authenticate by including the Client
   * Credentials in the request body.
   */
  CLIENT_SECRET_POST("client_secret_post"),

  // From JWT assertions (RFC 7523)

  /** Clients that have received a client_secret value create a JWT using an HMAC SHA algorithm. */
  CLIENT_SECRET_JWT("client_secret_jwt"),

  /** Clients that have registered a public key sign a JWT using that key. */
  PRIVATE_KEY_JWT("private_key_jwt"),
  ;

  private final String canonicalName;

  ClientAuthentication(String canonicalName) {
    this.canonicalName = canonicalName;
  }

  public boolean isClientSecret() {
    return this == CLIENT_SECRET_BASIC || this == CLIENT_SECRET_POST || this == CLIENT_SECRET_JWT;
  }

  public boolean isClientAssertion() {
    return this == PRIVATE_KEY_JWT || this == CLIENT_SECRET_JWT;
  }

  public String getCanonicalName() {
    return canonicalName;
  }

  public static ClientAuthentication fromConfigName(String name) {
    try {
      return valueOf(name.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException ignore) {
      name = name.toLowerCase(Locale.ROOT);
      for (ClientAuthentication method : values()) {
        if (method.canonicalName.equals(name)) {
          return method;
        }
      }
      throw new IllegalArgumentException("Unknown OAuth2 client authentication method: " + name);
    }
  }
}
