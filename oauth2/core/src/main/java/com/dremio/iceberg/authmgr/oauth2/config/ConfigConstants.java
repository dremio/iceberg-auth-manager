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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh;
import java.time.Duration;

final class ConfigConstants {

  static final Duration DEFAULT_TIMEOUT = Duration.parse(Basic.DEFAULT_TIMEOUT);
  static final Duration MIN_TIMEOUT = Duration.ofSeconds(30);

  static final String AUTHORIZATION_CODE_DEFAULT_CALLBACK_BIND_HOST = "localhost";

  static final Duration DEVICE_CODE_DEFAULT_POLL_INTERVAL =
      Duration.parse(DeviceCode.DEFAULT_POLL_INTERVAL);
  static final Duration DEVICE_CODE_MIN_POLL_INTERVAL =
      Duration.ofSeconds(5); // mandated by the specs

  static final Duration TOKEN_REFRESH_MIN_REFRESH_DELAY = Duration.ofSeconds(5);
  static final Duration TOKEN_REFRESH_MIN_IDLE_TIMEOUT = Duration.ofSeconds(30);
  static final Duration TOKEN_REFRESH_MIN_ACCESS_TOKEN_LIFESPAN = Duration.ofSeconds(30);
  static final Duration TOKEN_REFRESH_DEFAULT_IDLE_TIMEOUT =
      Duration.parse(TokenRefresh.DEFAULT_IDLE_TIMEOUT);
  static final Duration TOKEN_REFRESH_DEFAULT_SAFETY_WINDOW =
      Duration.parse(TokenRefresh.DEFAULT_SAFETY_WINDOW);
  static final Duration TOKEN_REFRESH_DEFAULT_ACCESS_TOKEN_LIFESPAN =
      Duration.parse(TokenRefresh.DEFAULT_ACCESS_TOKEN_LIFESPAN);

  private ConfigConstants() {}
}
