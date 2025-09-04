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

import static com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig.PREFIX;
import static org.assertj.core.api.Assertions.assertThat;

import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ResourceOwnerConfigTest {

  @Test
  void testAsMap() {
    Map<String, String> properties =
        Map.of(
            PREFIX + '.' + ResourceOwnerConfig.USERNAME, "username",
            PREFIX + '.' + ResourceOwnerConfig.PASSWORD, "password");
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(ResourceOwnerConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    ResourceOwnerConfig config = smallRyeConfig.getConfigMapping(ResourceOwnerConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}
