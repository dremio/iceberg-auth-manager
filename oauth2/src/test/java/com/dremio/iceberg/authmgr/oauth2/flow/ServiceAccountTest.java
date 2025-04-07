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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import org.junit.jupiter.api.Test;

class ServiceAccountTest {

  @Test
  void isPublicClient() {
    assertThat(ImmutableServiceAccount.builder().build().isPublicClient()).isFalse();
    assertThat(
            ImmutableServiceAccount.builder()
                .clientId(TestConstants.CLIENT_ID1)
                .build()
                .isPublicClient())
        .isTrue();
    assertThat(
            ImmutableServiceAccount.builder()
                .clientSecret(() -> TestConstants.CLIENT_SECRET1)
                .build()
                .isPublicClient())
        .isFalse();
    assertThat(
            ImmutableServiceAccount.builder()
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(() -> TestConstants.CLIENT_SECRET1)
                .build()
                .isPublicClient())
        .isFalse();
  }

  @Test
  void asBasicAuthHeader() {
    assertThat(ImmutableServiceAccount.builder().build().asBasicAuthHeader()).isNotPresent();
    assertThat(
            ImmutableServiceAccount.builder()
                .clientId(TestConstants.CLIENT_ID1)
                .build()
                .asBasicAuthHeader())
        .isNotPresent();
    assertThat(
            ImmutableServiceAccount.builder()
                .clientSecret(() -> TestConstants.CLIENT_SECRET1)
                .build()
                .asBasicAuthHeader())
        .isNotPresent();
    assertThat(
            ImmutableServiceAccount.builder()
                .clientId(TestConstants.CLIENT_ID1)
                .clientSecret(() -> TestConstants.CLIENT_SECRET1)
                .build()
                .asBasicAuthHeader())
        .contains("Basic " + TestConstants.CLIENT_CREDENTIALS1_BASE_64);
  }
}
