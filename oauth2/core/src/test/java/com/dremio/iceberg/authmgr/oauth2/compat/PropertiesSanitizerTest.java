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
package com.dremio.iceberg.authmgr.oauth2.compat;

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;

class PropertiesSanitizerTest {

  private ListAppender<ILoggingEvent> logAppender;
  private Logger logger;

  @BeforeEach
  void setUp() {
    logger = (Logger) LoggerFactory.getLogger(PropertiesSanitizer.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    logger.addAppender(logAppender);
    logger.setLevel(Level.WARN);
  }

  @AfterEach
  void tearDown() {
    logger.detachAppender(logAppender);
    logAppender.stop();
  }

  @Test
  void contextEmptyProperties() {
    Map<String, String> actual = PropertiesSanitizer.sanitizeContextProperties(Map.of());
    assertThat(actual).isEmpty();
    assertThat(logAppender.list).isEmpty();
  }

  @Test
  void contextAllowedProperties() {
    Map<String, String> input =
        Map.of(
            OAuth2Properties.Basic.CLIENT_ID,
            "client1",
            OAuth2Properties.Basic.CLIENT_SECRET,
            "secret",
            OAuth2Properties.Basic.TOKEN_ENDPOINT,
            "https://example.com/token",
            "custom.property",
            "value");
    Map<String, String> actual = PropertiesSanitizer.sanitizeContextProperties(input);
    assertThat(actual).isEqualTo(input);
    assertThat(logAppender.list).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("contextDenyListProperties")
  void contextForbiddenProperties(String forbiddenProperty) {
    Map<String, String> input =
        Map.of(forbiddenProperty, "forbidden", "allowed.property", "allowed");
    Map<String, String> actual = PropertiesSanitizer.sanitizeContextProperties(input);
    assertThat(actual).containsOnly(entry("allowed.property", "allowed"));
    assertThat(logAppender.list).hasSize(1);
    ILoggingEvent logEvent = logAppender.list.get(0);
    assertThat(logEvent.getLevel()).isEqualTo(Level.WARN);
    assertThat(logEvent.getFormattedMessage())
        .isEqualTo(
            "Ignoring property '"
                + forbiddenProperty
                + "': this property is not allowed in a session context.");
  }

  static Stream<String> contextDenyListProperties() {
    return PropertiesSanitizer.CONTEXT_DENY_LIST.stream();
  }

  @Test
  void tableEmptyProperties() {
    Map<String, String> actual = PropertiesSanitizer.sanitizeTableProperties(Map.of());
    assertThat(actual).isEmpty();
    assertThat(logAppender.list).isEmpty();
  }

  @Test
  void tableAllowedProperties() {
    Map<String, String> input =
        Map.of(
            OAuth2Properties.Basic.SCOPE,
            "read write",
            OAuth2Properties.Basic.TOKEN_ENDPOINT,
            "https://example.com/token",
            "custom.property",
            "value");
    Map<String, String> actual = PropertiesSanitizer.sanitizeTableProperties(input);
    assertThat(actual).isEqualTo(input);
    assertThat(logAppender.list).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("tableDenyListProperties")
  void tableForbiddenProperties(String forbiddenProperty) {
    Map<String, String> input =
        Map.of(forbiddenProperty, "forbidden", "allowed.property", "allowed");
    Map<String, String> actual = PropertiesSanitizer.sanitizeTableProperties(input);
    assertThat(actual).containsOnly(entry("allowed.property", "allowed"));
    assertThat(logAppender.list).hasSize(1);
    ILoggingEvent logEvent = logAppender.list.get(0);
    assertThat(logEvent.getLevel()).isEqualTo(Level.WARN);
    assertThat(logEvent.getFormattedMessage())
        .isEqualTo(
            "Ignoring property '"
                + forbiddenProperty
                + "': this property is not allowed to be vended by catalog servers.");
  }

  static Stream<String> tableDenyListProperties() {
    return PropertiesSanitizer.TABLE_DENY_LIST.stream();
  }
}
