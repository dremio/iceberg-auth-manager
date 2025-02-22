/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.config.validator;

import static java.lang.String.format;
import static java.lang.String.join;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.List;
import org.immutables.value.Value;

@AuthManagerImmutable
@Value.Style
interface ConfigViolation {

  @Value.Parameter(order = 1)
  List<String> getOffendingKeys();

  @Value.Parameter(order = 2)
  String getMessage();

  @Value.Lazy
  default String getFormattedMessage() {
    return getMessage() + " (" + join(" / ", getOffendingKeys()) + ")";
  }

  static ConfigViolation of(String offendingKey, String message) {
    return of(List.of(offendingKey), message);
  }

  static ConfigViolation of(String offendingKey, String message, Object... args) {
    return of(offendingKey, format(message, args));
  }

  static ConfigViolation of(List<String> offendingKeys, String message, Object... args) {
    return ImmutableConfigViolation.of(offendingKeys, format(message, args));
  }

  static ImmutableConfigViolation.Builder builder() {
    return ImmutableConfigViolation.builder();
  }
}
