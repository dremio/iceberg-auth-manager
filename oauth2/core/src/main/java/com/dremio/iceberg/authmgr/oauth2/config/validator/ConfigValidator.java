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
package com.dremio.iceberg.authmgr.oauth2.config.validator;

import com.google.errorprone.annotations.FormatMethod;
import com.google.errorprone.annotations.FormatString;
import com.nimbusds.jose.JWSAlgorithm;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ConfigValidator {

  private static final Logger LOGGER = LoggerFactory.getLogger(ConfigValidator.class);

  private final List<ConfigViolation> violations = new ArrayList<>();

  public void check(boolean cond, String offendingKey, String msg) {
    if (!cond) {
      violations.add(ConfigViolation.of(offendingKey, msg));
    }
  }

  public void check(boolean cond, List<String> offendingKeys, String msg) {
    if (!cond) {
      violations.add(ConfigViolation.of(offendingKeys, msg));
    }
  }

  @FormatMethod
  public void check(boolean cond, String offendingKey, @FormatString String msg, Object... args) {
    if (!cond) {
      violations.add(ConfigViolation.of(offendingKey, msg, args));
    }
  }

  @FormatMethod
  public void check(
      boolean cond, List<String> offendingKeys, @FormatString String msg, Object... args) {
    if (!cond) {
      violations.add(ConfigViolation.of(offendingKeys, msg, args));
    }
  }

  public void checkEndpoint(URI endpoint, String offendingKey, String name) {
    check(endpoint.isAbsolute(), offendingKey, name + " must not be relative");
    check(endpoint.getUserInfo() == null, offendingKey, name + " must not have a user info part");
    check(endpoint.getQuery() == null, offendingKey, name + " must not have a query part");
    check(endpoint.getFragment() == null, offendingKey, name + " must not have a fragment part");
  }

  public void checkAlgorithm(JWSAlgorithm algorithm) {
    if (algorithm.equals(JWSAlgorithm.RS256)
        || algorithm.equals(JWSAlgorithm.RS384)
        || algorithm.equals(JWSAlgorithm.RS512)) {
      LOGGER.warn(
          "JWS algorithm '{}' uses legacy PKCS#1 v1.5 RSA padding; "
              + "consider using PS256, PS384, or PS512 (RSASSA-PSS) instead",
          algorithm.getName());
    }
  }

  public void validate() {
    if (!violations.isEmpty()) {
      throw new IllegalArgumentException(
          buildDescription(violations.stream().map(ConfigViolation::getFormattedMessage)));
    }
  }

  private static final String DELIMITER = "\n  - ";

  public static String buildDescription(Stream<String> violations) {
    return "OAuth2 agent has configuration errors and could not be initialized:"
        + violations.collect(Collectors.joining(DELIMITER, DELIMITER, ""));
  }
}
