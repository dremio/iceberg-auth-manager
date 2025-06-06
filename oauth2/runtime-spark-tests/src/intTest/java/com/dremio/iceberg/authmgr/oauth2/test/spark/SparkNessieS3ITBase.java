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
package com.dremio.iceberg.authmgr.oauth2.test.spark;

import com.dremio.iceberg.authmgr.oauth2.test.container.NessieContainer;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.Network;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class SparkNessieS3ITBase extends SparkS3ITBase {

  protected volatile NessieContainer nessie;

  @Override
  protected CompletableFuture<Void> startAllContainers(Network network) {
    return CompletableFuture.allOf(
        super.startAllContainers(network),
        createNessieContainer(network)
            .thenCompose(
                container -> {
                  nessie = container;
                  return CompletableFuture.runAsync(container::start);
                })
            .thenCompose(v -> fetchNewToken()));
  }

  protected abstract CompletableFuture<NessieContainer> createNessieContainer(Network network);

  protected abstract CompletableFuture<String> fetchNewToken();

  @Override
  protected URI catalogApiEndpoint() {
    return nessie.getIcebergRestApiEndpoint();
  }

  @AfterAll
  @Override
  public void stopAllContainers() {
    var nessie = this.nessie;
    try (nessie) {
      super.stopAllContainers();
    }
  }
}
