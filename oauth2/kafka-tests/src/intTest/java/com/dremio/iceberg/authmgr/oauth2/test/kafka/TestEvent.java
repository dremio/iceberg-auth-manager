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
package com.dremio.iceberg.authmgr.oauth2.test.kafka;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Schema;
import org.apache.iceberg.types.Types;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.data.Timestamp;
import org.apache.kafka.connect.json.JsonConverter;
import org.apache.kafka.connect.storage.ConverterConfig;
import org.apache.kafka.connect.storage.ConverterType;

public record TestEvent(long id, String type, Instant ts, String payload, String op) {

  public static final Schema ICEBERG_SCHEMA =
      new Schema(
          List.of(
              Types.NestedField.required(1, "id", Types.LongType.get()),
              Types.NestedField.required(2, "type", Types.StringType.get()),
              Types.NestedField.required(3, "ts", Types.TimestampType.withZone()),
              Types.NestedField.required(4, "payload", Types.StringType.get())),
          Set.of(1));

  public static final org.apache.kafka.connect.data.Schema KAFKA_SCHEMA =
      SchemaBuilder.struct()
          .field("id", org.apache.kafka.connect.data.Schema.INT64_SCHEMA)
          .field("type", org.apache.kafka.connect.data.Schema.STRING_SCHEMA)
          .field("ts", Timestamp.SCHEMA)
          .field("payload", org.apache.kafka.connect.data.Schema.STRING_SCHEMA)
          .field("op", org.apache.kafka.connect.data.Schema.OPTIONAL_STRING_SCHEMA);

  public static final PartitionSpec ICEBERG_SPEC =
      PartitionSpec.builderFor(ICEBERG_SCHEMA).day("ts").build();

  private static final JsonConverter JSON_CONVERTER = new JsonConverter();

  static {
    JSON_CONVERTER.configure(Map.of(ConverterConfig.TYPE_CONFIG, ConverterType.VALUE.getName()));
  }

  public byte[] serialize(String topic) {
    Struct value =
        new Struct(KAFKA_SCHEMA)
            .put("id", id)
            .put("type", type)
            .put("ts", Date.from(ts))
            .put("payload", payload)
            .put("op", op);
    return JSON_CONVERTER.fromConnectData(topic, KAFKA_SCHEMA, value);
  }
}
