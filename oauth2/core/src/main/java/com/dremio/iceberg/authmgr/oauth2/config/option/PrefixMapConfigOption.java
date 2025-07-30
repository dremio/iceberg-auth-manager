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
package com.dremio.iceberg.authmgr.oauth2.config.option;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import org.apache.iceberg.rest.RESTUtil;
import org.immutables.value.Value;

/**
 * A "prefix map" configuration option that can be set from multiple configuration properties that
 * share a common prefix.
 */
@AuthManagerImmutable
abstract class PrefixMapConfigOption extends ConfigOption<Map<String, String>> {

  /** The common prefix for the configuration properties. */
  protected abstract String prefix();

  /** An optional replacement prefix for the configuration properties. */
  protected abstract Optional<String> replacementPrefix();

  @Value.Check
  protected void check() {
    if (prefix().isEmpty()) {
      throw new IllegalArgumentException("Prefix cannot be empty");
    }
    if (replacementPrefix().isPresent() && replacementPrefix().get().isEmpty()) {
      throw new IllegalArgumentException("Replacement prefix cannot be empty");
    }
  }

  @Override
  public void set(Map<String, String> properties) {
    Map<String, String> updates = RESTUtil.extractPrefixMap(properties, prefix());
    if (!updates.isEmpty()) {
      Map<String, String> merged = new HashMap<>(fallback().orElseGet(Map::of));
      for (Entry<String, String> entry : updates.entrySet()) {
        String value = entry.getValue();
        String key = replacementPrefix().map(p -> p + entry.getKey()).orElseGet(entry::getKey);
        if (shouldSetOption(value)) {
          merged.put(key, value.trim());
        } else {
          // By convention: consider an empty or null value as a map entry removal
          merged.remove(key);
        }
      }
      setter().accept(merged);
    } else {
      fallback().ifPresent(setter());
    }
  }
}
