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
package com.dremio.iceberg.authmgr.oauth2.token.provider;

import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import jakarta.annotation.Nullable;
import org.immutables.value.Value;

@AuthManagerImmutable
@Value.Immutable(singleton = true)
abstract class NullTokenProvider implements TokenProvider {

  @Nullable
  @Override
  public final TypedToken provideToken(@Nullable AccessToken accessToken) {
    return null;
  }
}
