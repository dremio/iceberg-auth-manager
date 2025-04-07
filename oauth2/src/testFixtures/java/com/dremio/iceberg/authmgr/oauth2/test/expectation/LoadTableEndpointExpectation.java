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

import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getJsonBody;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.UUID;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Schema;
import org.apache.iceberg.SortOrder;
import org.apache.iceberg.TableMetadata;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.apache.iceberg.types.Types;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

@AuthManagerImmutable
public abstract class LoadTableEndpointExpectation extends AbstractExpectation {

  @Override
  public void create() {
    TableMetadata metadata =
        TableMetadata.buildFromEmpty(1)
            .assignUUID(UUID.randomUUID().toString())
            .setLocation("s3://bucket")
            .setCurrentSchema(
                new Schema(Types.NestedField.required(1, "x", Types.LongType.get())), 1)
            .addPartitionSpec(PartitionSpec.unpartitioned())
            .addSortOrder(SortOrder.unsorted())
            .discardChanges()
            .withMetadataLocation("s3://bucket/metadata")
            .build();
    LoadTableResponse response =
        LoadTableResponse.builder()
            .withTableMetadata(metadata)
            .addAllConfig(getTestEnvironment().getTableProperties())
            .build();
    getClientAndServer()
        .when(
            HttpRequest.request()
                .withMethod("GET")
                .withPath(getTestEnvironment().getLoadTableEndpoint().getPath())
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json")
                .withHeader("Authorization", "Bearer access_initial2?"))
        .respond(HttpResponse.response().withBody(getJsonBody(response)));
  }
}
