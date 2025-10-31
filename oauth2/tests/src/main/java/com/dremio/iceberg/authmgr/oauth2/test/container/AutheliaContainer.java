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
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

public class AutheliaContainer extends GenericContainer<AutheliaContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(AutheliaContainer.class);

  @SuppressWarnings("resource")
  public AutheliaContainer(
      String privateKeyClasspathResource, String certificateClasspathResource) {
    super("authelia/authelia:4.39.13");
    withExposedPorts(9091);
    withEnv("X_AUTHELIA_CONFIG_FILTERS", "template");
    withEnv("AUTHMGR_LOG_LEVEL", getLogLevel());

    withClasspathResourceMapping(
        "authelia/authelia-config.yaml", "/config/configuration.yml", BindMode.READ_ONLY);
    withClasspathResourceMapping(
        "authelia/authelia-users.yaml", "/config/users.yml", BindMode.READ_ONLY);
    withClasspathResourceMapping(
        privateKeyClasspathResource, "/config/key.pem", BindMode.READ_ONLY);
    withClasspathResourceMapping(
        certificateClasspathResource, "/config/cert.pem", BindMode.READ_ONLY);

    waitingFor(Wait.forListeningPort());
  }

  public URI getAutheliaUrl() {
    return URI.create("https://localhost:" + getMappedPort(9091));
  }

  private static String getLogLevel() {
    return LOGGER.isDebugEnabled()
        ? "debug"
        : LOGGER.isInfoEnabled() ? "info" : LOGGER.isWarnEnabled() ? "warn" : "error";
  }
}
