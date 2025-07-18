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
package com.dremio.iceberg.authmgr.oauth2.test.user;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.Optional;
import org.immutables.value.Value;

/** Describes the desired behavior of a user when interacting with the authorization server. */
@AuthManagerImmutable
public interface UserBehavior {

  /**
   * A simplified user behavior for unit tests, which don't expect a login page but instead expect
   * the authorization server to accept the provided credentials directly.
   */
  UserBehavior UNIT_TESTS = builder().build();

  /**
   * A user behavior for integration tests, which expects a login page and uses the provided
   * credentials to log in.
   */
  UserBehavior INTEGRATION_TESTS =
      builder().username(TestConstants.USERNAME).password(TestConstants.PASSWORD).build();

  static ImmutableUserBehavior.Builder builder() {
    return ImmutableUserBehavior.builder();
  }

  /**
   * An optional username to use when logging in to the authorization server. A username is only
   * required when running integration tests against a real authorization server.
   */
  Optional<String> getUsername();

  /**
   * An optional password to use when logging in to the authorization server. A password is only
   * required when running integration tests against a real authorization server.
   */
  Optional<String> getPassword();

  default String getRequiredPassword() {
    return getPassword().orElseThrow(() -> new IllegalStateException("Password is required"));
  }

  default String getRequiredUsername() {
    return getUsername().orElseThrow(() -> new IllegalStateException("Username is required"));
  }

  /**
   * Whether to emulate a user failure, for example by entering a wrong code or by denying consent.
   */
  @Value.Default
  default boolean isEmulateFailure() {
    return false;
  }
}
