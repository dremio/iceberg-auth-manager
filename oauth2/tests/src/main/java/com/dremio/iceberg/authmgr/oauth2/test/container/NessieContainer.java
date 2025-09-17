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
package com.dremio.iceberg.authmgr.oauth2.test.container;

import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

/** A test container for Nessie servers. */
public class NessieContainer extends GenericContainer<NessieContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(NessieContainer.class);

  private URI baseUri;

  @SuppressWarnings("resource")
  public NessieContainer() {
    super("ghcr.io/projectnessie/nessie:0.105.1");
    withNetworkAliases("nessie");
    withLogConsumer(new Slf4jLogConsumer(LOGGER));
    withExposedPorts(19120, 9000);
    waitingFor(Wait.forHttp("/q/health/ready").forPort(9000));
    withEnv("nessie.version.store.type", "IN_MEMORY");
    withEnv("quarkus.log.level", getRootLoggerLevel());
    withEnv("quarkus.log.console.level", getRootLoggerLevel());
    withEnv("quarkus.log.category.\"org.projectnessie\".level", getNessieLoggerLevel());
  }

  @Override
  public void start() {
    if (getContainerId() != null) {
      return;
    }
    super.start();
    baseUri = URI.create("http://localhost:" + getMappedPort(19120));
  }

  /** Returns the Iceberg REST API endpoint URI. */
  public URI getIcebergRestApiEndpoint() {
    return baseUri.resolve("/iceberg");
  }

  private static String getRootLoggerLevel() {
    return LOGGER.isInfoEnabled() ? "INFO" : LOGGER.isWarnEnabled() ? "WARN" : "ERROR";
  }

  private static String getNessieLoggerLevel() {
    return LOGGER.isDebugEnabled() ? "DEBUG" : getRootLoggerLevel();
  }
}
