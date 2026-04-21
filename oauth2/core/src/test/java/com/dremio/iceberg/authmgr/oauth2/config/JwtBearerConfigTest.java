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

import static com.dremio.iceberg.authmgr.oauth2.config.JwtBearerConfig.ASSERTION_FILE;
import static com.dremio.iceberg.authmgr.oauth2.config.JwtBearerConfig.PREFIX;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JwtBearerConfigTest {

  @Test
  void testValidateAssertionFile() {
    Map<String, String> properties =
        Map.of(PREFIX + '.' + ASSERTION_FILE, "/invalid/assertion-file");
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(JwtBearerConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    JwtBearerConfig config = smallRyeConfig.getConfigMapping(JwtBearerConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(
            ConfigValidator.buildDescription(
                singletonList(
                    "jwt-bearer: '/invalid/assertion-file' is not a file or is not readable ("
                        + PREFIX
                        + '.'
                        + ASSERTION_FILE
                        + ")")
                    .stream()));
  }
}
