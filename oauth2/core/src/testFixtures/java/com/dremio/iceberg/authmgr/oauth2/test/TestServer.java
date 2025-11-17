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
package com.dremio.iceberg.authmgr.oauth2.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.mockserver.configuration.Configuration;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;

public final class TestServer {

  private static final ClientAndServer INSTANCE;

  static {
    Configuration configuration = Configuration.configuration();
    String outputDir = System.getProperty("authmgr.test.mockserver.memoryUsageCsvDirectory");
    if (outputDir != null) {
      Path outputPath = Paths.get(outputDir);
      try {
        Files.createDirectories(outputPath);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      configuration.outputMemoryUsageCsv(true);
      configuration.memoryUsageCsvDirectory(outputPath.toString());
    }
    INSTANCE = ClientAndServer.startClientAndServer(configuration);
    Runtime.getRuntime().addShutdownHook(new Thread(INSTANCE::close));
  }

  private TestServer() {}

  public static ClientAndServer getInstance() {
    return INSTANCE;
  }

  /** Clears all expectations and responses for the given test environment id. */
  public static void clear(String testEnvironmentId) {
    INSTANCE.clear(HttpRequest.request().withPath("/" + testEnvironmentId + "/.*"));
  }
}
