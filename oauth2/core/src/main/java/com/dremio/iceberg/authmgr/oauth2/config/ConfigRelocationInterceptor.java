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
import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigRelocationInterceptor implements ConfigSourceInterceptor {

  private static final Logger LOGGER = LoggerFactory.getLogger(ConfigRelocationInterceptor.class);
  private static final String ROOT_PREFIX = OAuth2Config.PREFIX + '.';

  private static final List<RelocationRule> RELOCATION_RULES =
      List.of(
          new RelocationRule(
              Pattern.compile("\\.callback-"),
              ".callback.",
              Pattern.compile("\\.callback\\."),
              ".callback-"));

  @Override
  public Iterator<String> iterateNames(ConfigSourceInterceptorContext context) {
    // Only include relocated (canonical) names; filter out legacy aliases
    // to avoid mapping errors "SRCFG00050 ... does not map to any root"
    Set<String> canonicalNames = new LinkedHashSet<>();
    Iterator<String> names = context.iterateNames();
    while (names.hasNext()) {
      canonicalNames.add(toCanonicalName(names.next()));
    }
    return canonicalNames.iterator();
  }

  @Override
  public ConfigValue getValue(ConfigSourceInterceptorContext context, String name) {
    if (!name.startsWith(ROOT_PREFIX)) {
      return context.proceed(name);
    }
    String canonicalName = toCanonicalName(name);
    Set<String> candidates = new LinkedHashSet<>();
    candidates.add(canonicalName);
    candidates.add(toLegacyName(canonicalName));
    ConfigValue selected = null;
    for (String candidate : candidates) {
      ConfigValue value = context.proceed(candidate);
      if (value != null
          && (selected == null
              || ConfigValue.CONFIG_SOURCE_COMPARATOR.compare(value, selected) >= 0)) {
        selected = value.withName(canonicalName);
      }
    }
    if (selected != null && !name.equals(canonicalName)) {
      LOGGER.warn("Property '{}' is deprecated, use '{}' instead", name, canonicalName);
    }
    return selected;
  }

  public static String toCanonicalName(String name) {
    String canonicalName = name;
    for (RelocationRule rule : RELOCATION_RULES) {
      canonicalName = rule.toCanonicalName(canonicalName);
    }
    return canonicalName;
  }

  static String toLegacyName(String name) {
    String legacyName = name;
    for (RelocationRule rule : RELOCATION_RULES) {
      legacyName = rule.toLegacyName(legacyName);
    }
    return legacyName;
  }

  private static final class RelocationRule {

    private final Pattern canonicalPattern;
    private final String canonicalReplacement;

    private final Pattern legacyPattern;
    private final String legacyReplacement;

    private RelocationRule(
        Pattern canonicalPattern,
        String canonicalReplacement,
        Pattern legacyPattern,
        String legacyReplacement) {
      this.canonicalPattern = canonicalPattern;
      this.canonicalReplacement = canonicalReplacement;
      this.legacyPattern = legacyPattern;
      this.legacyReplacement = legacyReplacement;
    }

    public String toCanonicalName(String name) {
      return name.startsWith(ROOT_PREFIX)
          ? canonicalPattern.matcher(name).replaceAll(canonicalReplacement)
          : name;
    }

    public String toLegacyName(String name) {
      return name.startsWith(ROOT_PREFIX)
          ? legacyPattern.matcher(name).replaceAll(legacyReplacement)
          : name;
    }
  }
}
