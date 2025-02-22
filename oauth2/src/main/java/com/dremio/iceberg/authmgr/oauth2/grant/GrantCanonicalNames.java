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
package com.dremio.iceberg.authmgr.oauth2.grant;

/** Canonical names for OAuth2 grant types, as defined in the OAuth2 specification. */
public final class GrantCanonicalNames {

  public static final String CLIENT_CREDENTIALS = "client_credentials";
  public static final String PASSWORD = "password";
  public static final String AUTHORIZATION_CODE = "authorization_code";
  public static final String DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
  public static final String REFRESH_TOKEN = "refresh_token";
  public static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

  private GrantCanonicalNames() {}
}
