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
package com.dremio.iceberg.authmgr.oauth2.test.expectation;

import static org.mockserver.model.Parameter.param;

import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.iceberg.rest.RESTResponse;
import org.apache.iceberg.rest.RESTSerializers;
import org.mockserver.model.JsonBody;
import org.mockserver.model.Parameter;
import org.mockserver.model.ParameterBody;

public final class ExpectationUtils {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();

  static {
    RESTSerializers.registerAll(OBJECT_MAPPER);
  }

  public static JsonBody getJsonBody(RESTResponse body) {
    try {
      return JsonBody.json(OBJECT_MAPPER.writeValueAsString(body));
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static ParameterBody getParameterBody(PostFormRequest body) {
    List<Parameter> parameters =
        body.asFormParameters().entrySet().stream()
            .map(entry -> param(entry.getKey(), entry.getValue()))
            .collect(Collectors.toList());
    return ParameterBody.params(parameters);
  }
}
