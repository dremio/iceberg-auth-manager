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
package com.dremio.iceberg.authmgr.oauth2.core.expectation;

import com.dremio.iceberg.authmgr.oauth2.core.IcebergTestEnvironment;
import com.dremio.oauth2.agent.expectation.AbstractExpectation;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.iceberg.rest.RESTResponse;
import org.apache.iceberg.rest.RESTSerializers;
import org.immutables.value.Value;
import org.mockserver.model.JsonBody;

public abstract class IcebergRestExpectation extends AbstractExpectation {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  static {
    RESTSerializers.registerAll(OBJECT_MAPPER);
  }

  @Value.Parameter(order = 1)
  @Override
  protected abstract IcebergTestEnvironment getTestEnvironment();

  protected JsonBody getJsonBody(RESTResponse response) {
    try {
      return JsonBody.json(OBJECT_MAPPER.writeValueAsString(response));
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }
}
