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
package com.dremio.iceberg.authmgr.oauth2.config;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.USERNAME;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@AuthManagerImmutable
public interface ResourceOwnerConfig {

  ResourceOwnerConfig DEFAULT = builder().build();

  /**
   * The OAuth2 username. Only relevant for {@link GrantType#PASSWORD} grant type.
   *
   * @see OAuth2Properties.ResourceOwner#USERNAME
   */
  Optional<String> getUsername();

  /**
   * The OAuth2 password supplier. Only relevant for {@link GrantType#PASSWORD} grant type. Must be
   * set if a password is required.
   */
  Optional<Secret> getPassword();

  /** Merges the given properties into this {@link ResourceOwnerConfig} and returns the result. */
  default ResourceOwnerConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    ResourceOwnerConfig.Builder builder = builder();
    builder.usernameOption().set(properties, getUsername());
    builder.passwordOption().set(properties, getPassword());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableResourceOwnerConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(ResourceOwnerConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      usernameOption().set(properties);
      passwordOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder username(String username);

    @CanIgnoreReturnValue
    default Builder password(String password) {
      return password(Secret.of(password));
    }

    @CanIgnoreReturnValue
    Builder password(Secret password);

    ResourceOwnerConfig build();

    private ConfigOption<String> usernameOption() {
      return ConfigOptions.simple(USERNAME, this::username);
    }

    private ConfigOption<Secret> passwordOption() {
      return ConfigOptions.simple(PASSWORD, this::password, Secret::of);
    }
  }
}
