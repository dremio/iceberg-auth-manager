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

import io.smallrye.config.RelocateConfigSourceInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigRelocationInterceptor extends RelocateConfigSourceInterceptor {

  private static final Logger LOGGER = LoggerFactory.getLogger(ConfigRelocationInterceptor.class);

  public ConfigRelocationInterceptor() {
    super(ConfigRelocationInterceptor::applyRelocations);
  }

  private static String applyRelocations(String name) {
    // rest.auth.oauth2.auth-code.callback- > rest.auth.oauth2.auth-code.callback.
    if (name.startsWith(AuthorizationCodeConfig.PREFIX + ".callback-")) {
      String replacement = name.replace(".callback-", ".callback.");
      LOGGER.warn("Property '{}' is deprecated, use '{}' instead", name, replacement);
      return replacement;
    }
    return name;
  }
}
