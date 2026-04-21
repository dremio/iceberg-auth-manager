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

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

public class AutheliaContainer extends GenericContainer<AutheliaContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(AutheliaContainer.class);

  // Pre-allocated host port so it can be passed to Authelia via env var before container start.
  // Authelia 4.39.14+ enforces that the OIDC discovery URL's origin (scheme+host+port) matches
  // a configured session cookie domain URL, so authelia_url must include the exact mapped port.
  private final int hostPort;

  @SuppressWarnings("resource")
  public AutheliaContainer(Path privateKeyPath, Path certificatePath) {
    super("authelia/authelia:4.39.19");
    this.hostPort = allocateFreePort();
    addFixedExposedPort(hostPort, 9091);
    withEnv("X_AUTHELIA_CONFIG_FILTERS", "template");
    withEnv("AUTHMGR_LOG_LEVEL", getLogLevel());
    withEnv("AUTHELIA_URL", "https://127.0.0.1:" + hostPort);

    withClasspathResourceMapping(
        "authelia/authelia-config.yaml", "/config/configuration.yml", BindMode.READ_ONLY);
    withClasspathResourceMapping(
        "authelia/authelia-users.yaml", "/config/users.yml", BindMode.READ_ONLY);
    withFileSystemBind(
        privateKeyPath.toAbsolutePath().toString(), "/config/key.pem", BindMode.READ_ONLY);
    withFileSystemBind(
        certificatePath.toAbsolutePath().toString(), "/config/cert.pem", BindMode.READ_ONLY);

    waitingFor(Wait.forListeningPort());
  }

  public URI getAutheliaUrl() {
    return URI.create("https://127.0.0.1:" + hostPort);
  }

  private static int allocateFreePort() {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    } catch (IOException e) {
      throw new RuntimeException("Cannot allocate free port for Authelia container", e);
    }
  }

  private static String getLogLevel() {
    return LOGGER.isDebugEnabled()
        ? "debug"
        : LOGGER.isInfoEnabled() ? "info" : LOGGER.isWarnEnabled() ? "warn" : "error";
  }
}
