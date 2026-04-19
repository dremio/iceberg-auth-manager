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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration properties for the JWT bearer grant as specified in <a
 * href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523</a>.
 *
 * <p>The assertion can be supplied statically or fetched dynamically using a nested OAuth2
 * configuration.
 */
public interface JwtBearerConfig {

  String GROUP_NAME = "jwt-bearer";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ASSERTION = "assertion";
  String ASSERTION_FILE = "assertion-file";

  /**
   * The assertion to exchange.
   *
   * <p>If this value is present, the assertion is used as-is. If this value is not present, the
   * assertion may be read from the file specified by {@value #ASSERTION_FILE}, or dynamically
   * fetched using the configuration provided under the {@value #ASSERTION} prefix.
   */
  @WithName(ASSERTION)
  Optional<String> getAssertion();

  /**
   * Path to a file containing the assertion. The file content is read and trimmed to obtain the
   * assertion value. Ignored if {@value #ASSERTION} is set.
   */
  @WithName(ASSERTION_FILE)
  Optional<Path> getAssertionFile();

  /**
   * The configuration to use for fetching the assertion dynamically.
   *
   * <p>This is a prefix property; any property that can be set under the {@value
   * OAuth2Config#PREFIX} prefix can also be set under this prefix.
   */
  @WithName(ASSERTION)
  Map<String, String> getAssertionConfig();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    Path assertionFilePath = getAssertionFile().orElse(null);
    if (getAssertion().isEmpty() && assertionFilePath != null) {
      validator.check(
          Files.isReadable(assertionFilePath),
          PREFIX + '.' + ASSERTION_FILE,
          "jwt-bearer: '%s' is not a file or is not readable",
          assertionFilePath);
    }
    validator.validate();
  }
}
