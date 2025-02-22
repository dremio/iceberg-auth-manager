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

/**
 * Common names for OAuth2 grant types, used in the configuration. These names are accepted in
 * configuration options for the sake of simplicity, although they are not necessarily the same as
 * the names used in the OAuth2 specification.
 */
public final class GrantCommonNames {

  public static final String CLIENT_CREDENTIALS = GrantCanonicalNames.CLIENT_CREDENTIALS;
  public static final String PASSWORD = GrantCanonicalNames.PASSWORD;
  public static final String AUTHORIZATION_CODE = GrantCanonicalNames.AUTHORIZATION_CODE;
  public static final String REFRESH_TOKEN = GrantCanonicalNames.REFRESH_TOKEN;

  public static final String DEVICE_CODE = "device_code";
  public static final String TOKEN_EXCHANGE = "token_exchange";

  private GrantCommonNames() {}
}
