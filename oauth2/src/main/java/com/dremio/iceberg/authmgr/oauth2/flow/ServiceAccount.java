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

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ImpersonationConfig;
import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * A service account, composed of a client ID and / or a client secret.
 *
 * <p>Two configuration classes are used to represent a service account:
 *
 * <ul>
 *   <li>{@link BasicConfig} - a client ID and secret pair for normal token fetches;
 *   <li>{@link ImpersonationConfig} - an alternate client ID and secret pair for token fetches with
 *       impersonation.
 */
@AuthManagerImmutable
public interface ServiceAccount {

  Optional<String> getClientId();

  Optional<Secret> getClientSecret();

  default boolean isPublicClient() {
    return getClientId().isPresent() && getClientSecret().isEmpty();
  }

  /**
   * Returns a Basic Auth header for this client ID and secret, if both are present. Returns empty
   * if either the client ID or secret are missing.
   */
  default Optional<String> asBasicAuthHeader() {
    return getClientId()
        .flatMap(id -> getClientSecret().map(secret -> id + ":" + secret.getSecret()))
        .map(creds -> creds.getBytes(StandardCharsets.UTF_8))
        .map(creds -> Base64.getEncoder().encodeToString(creds))
        .map(creds -> "Basic " + creds);
  }
}
