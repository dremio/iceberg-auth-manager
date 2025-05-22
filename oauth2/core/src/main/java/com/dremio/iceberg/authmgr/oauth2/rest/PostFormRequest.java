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
package com.dremio.iceberg.authmgr.oauth2.rest;

import java.util.Map;
import org.immutables.value.Value.Redacted;

/**
 * A POST request with form parameters, to be encoded using the {@value #CONTENT_TYPE} content type.
 */
public interface PostFormRequest {

  String CONTENT_TYPE = "application/x-www-form-urlencoded";

  /** Get the form parameters for the POST request. The parameters should NOT be URL-encoded. */
  @Redacted
  Map<String, String> asFormParameters();
}
