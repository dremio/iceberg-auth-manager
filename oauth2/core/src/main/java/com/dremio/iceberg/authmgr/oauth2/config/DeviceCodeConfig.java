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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import io.smallrye.config.WithName;
import java.net.URI;
import java.util.Optional;

/**
 * Configuration properties for the <a href="https://datatracker.ietf.org/doc/html/rfc8628">Device
 * Authorization Grant</a> flow.
 *
 * <p>This flow is used to obtain an access token for devices that do not have a browser or limited
 * input capabilities. The user is prompted to visit a URL on another device and enter a code to
 * authorize the device.
 */
public interface DeviceCodeConfig {

  String GROUP_NAME = "device-code";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ENDPOINT = "endpoint";

  /**
   * URL of the OAuth2 device authorization endpoint. For Keycloak, this is typically {@code
   * http://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth/device}.
   *
   * <p>If using the "Device Code" grant type, either this property or {@link
   * BasicConfig#ISSUER_URL} must be set.
   */
  @WithName(ENDPOINT)
  Optional<URI> getDeviceAuthorizationEndpoint();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getDeviceAuthorizationEndpoint().isPresent()) {
      validator.checkEndpoint(
          getDeviceAuthorizationEndpoint().get(),
          PREFIX + '.' + ENDPOINT,
          "device code flow: device authorization endpoint");
    }
    validator.validate();
  }
}
