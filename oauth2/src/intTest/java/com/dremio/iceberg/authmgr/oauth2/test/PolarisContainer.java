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

import java.net.URI;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;

public class PolarisContainer implements AutoCloseable {

  private static final Logger LOGGER = LoggerFactory.getLogger(PolarisContainer.class);

  private static final Duration ACCESS_TOKEN_LIFESPAN = Duration.ofSeconds(15);

  private final GenericContainer<?> polaris;
  private final URI baseUri;
  private final URI tokenEndpoint;

  @SuppressWarnings("resource")
  public PolarisContainer() {
    polaris =
        new GenericContainer<>("apache/polaris:latest")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER))
            .withExposedPorts(8181, 8182)
            .waitingFor(
                new HttpWaitStrategy()
                    .forPath("/q/health")
                    .forPort(8182)
                    .forResponsePredicate(body -> body.contains("\"status\": \"UP\"")))
            .withEnv(
                "POLARIS_BOOTSTRAP_CREDENTIALS",
                "POLARIS," + TestConstants.CLIENT_ID1 + "," + TestConstants.CLIENT_SECRET1)
            .withEnv(
                "polaris.features.defaults.\"ALLOW_EXTERNAL_CATALOG_CREDENTIAL_VENDING\"", "false")
            .withEnv(
                "polaris-authentication.token-broker.max-token-generation",
                ACCESS_TOKEN_LIFESPAN.toString())
            .withEnv("quarkus.log.level", getRootLoggerLevel())
            .withEnv("quarkus.log.category.\"org.apache.polaris\".level", getPolarisLoggerLevel());
    polaris.start();
    baseUri = URI.create("http://localhost:" + polaris.getMappedPort(8181));
    tokenEndpoint = baseUri.resolve("/api/catalog/v1/oauth/tokens");
  }

  public URI baseUri() {
    return baseUri;
  }

  public URI getTokenEndpoint() {
    return tokenEndpoint;
  }

  public Duration getAccessTokenLifespan() {
    return ACCESS_TOKEN_LIFESPAN;
  }

  @Override
  public void close() {
    polaris.stop();
  }

  private static String getRootLoggerLevel() {
    return LOGGER.isInfoEnabled() ? "INFO" : LOGGER.isWarnEnabled() ? "WARN" : "ERROR";
  }

  private static String getPolarisLoggerLevel() {
    return LOGGER.isDebugEnabled() ? "DEBUG" : getRootLoggerLevel();
  }
}
