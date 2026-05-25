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
package com.dremio.oauth2.agent.expectation;

import com.dremio.oauth2.agent.TestEnvironment;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.immutables.value.Value;
import org.mockserver.model.JsonBody;
import org.mockserver.model.Parameter;
import org.mockserver.model.ParameterBody;

public abstract class AbstractExpectation {

  @Value.Parameter(order = 1)
  protected abstract TestEnvironment getTestEnvironment();

  public abstract void create();

  protected JsonBody getJsonBody(Map<String, Object> response) {
    return JsonBody.json(response);
  }

  protected ParameterBody getParameterBody(Map<String, String> request) {
    List<Parameter> parameters =
        request.entrySet().stream()
            .map(entry -> Parameter.param(entry.getKey(), entry.getValue()))
            .collect(Collectors.toList());
    return ParameterBody.params(parameters);
  }
}
