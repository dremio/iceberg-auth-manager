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

import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.server.UnitTestHttpServer;
import org.immutables.value.Value;
import org.mockserver.integration.ClientAndServer;

public abstract class AbstractExpectation {

  @Value.Parameter(order = 1)
  protected abstract TestEnvironment getTestEnvironment();

  public abstract void create();

  protected ClientAndServer getClientAndServer() {
    return ((UnitTestHttpServer) getTestEnvironment().getServer()).getClientAndServer();
  }
}
