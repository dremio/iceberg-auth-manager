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
package com.dremio.iceberg.authmgr.oauth2.token;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.URI;

/** Represents a token with a specific type URI. Such tokens are used in the Token Exchange flow. */
@AuthManagerImmutable
public interface TypedToken extends Token {

  /** Indicates that the token is an OAuth 2.0 access token. */
  URI URN_ACCESS_TOKEN = URI.create("urn:ietf:params:oauth:token-type:access_token");

  /** Indicates that the token is an OAuth 2.0 refresh token. */
  URI URN_REFRESH_TOKEN = URI.create("urn:ietf:params:oauth:token-type:refresh_token");

  /** Indicates that the token is an OpenID Core ID Token. */
  URI URN_ID_TOKEN = URI.create("urn:ietf:params:oauth:token-type:id_token");

  /** Indicates that the token is a base64url-encoded SAML 1.1 assertion. */
  URI URN_SAML1 = URI.create("urn:ietf:params:oauth:token-type:saml1");

  /** Indicates that the token is a base64url-encoded SAML 2.0 assertion. */
  URI URN_SAML2 = URI.create("urn:ietf:params:oauth:token-type:saml2");

  /** Indicates that the token is a JWT. */
  URI URN_JWT = URI.create("urn:ietf:params:oauth:token-type:jwt");

  /** The type of the token. */
  URI getTokenType();

  static TypedToken of(String payload, URI type) {
    return ImmutableTypedToken.builder().payload(payload).tokenType(type).build();
  }

  static TypedToken of(Token token, URI type) {
    return ImmutableTypedToken.builder().from(token).tokenType(type).build();
  }

  static TypedToken of(AccessToken accessToken) {
    return of(accessToken, URN_ACCESS_TOKEN);
  }
}
