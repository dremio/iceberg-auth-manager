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
package com.dremio.iceberg.authmgr.oauth2.endpoint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.assertj.core.api.InstanceOfAssertFactories.throwable;

import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.rest.MetadataDiscoveryResponse;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.server.UnitTestHttpServer;
import org.apache.iceberg.exceptions.RESTException;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.JsonBody;
import org.mockserver.model.MediaType;

class EndpointProviderTest {

  private static final String INVALID_METADATA =
      "{"
          + "\"authorization_endpoint\":\"http://server.com/realms/master/protocol/openid-connect/auth\","
          + "\"token_endpoint\":\"http://server.com/realms/master/protocol/openid-connect/token\""
          + "}";

  @Test
  void withoutDiscovery() {
    try (TestEnvironment env =
        TestEnvironment.builder().discoveryEnabled(false).impersonationEnabled(true).build()) {
      // primary
      EndpointProvider endpointProvider = env.getEndpointProvider();
      assertThat(endpointProvider.getResolvedTokenEndpoint()).isEqualTo(env.getTokenEndpoint());
      assertThat(endpointProvider.getResolvedAuthorizationEndpoint())
          .isEqualTo(env.getAuthorizationEndpoint());
      assertThat(endpointProvider.getResolvedDeviceAuthorizationEndpoint())
          .isEqualTo(env.getDeviceAuthorizationEndpoint());
      // impersonation
      EndpointProvider impersonatinEndpointProvider = env.getImpersonatinEndpointProvider();
      assertThat(impersonatinEndpointProvider.getResolvedTokenEndpoint())
          .isEqualTo(env.getImpersonationTokenEndpoint());
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void withDiscovery(boolean includeDeviceAuthEndpoint) {
    try (TestEnvironment env =
        TestEnvironment.builder()
            .impersonationEnabled(true)
            .includeDeviceAuthEndpointInDiscoveryMetadata(includeDeviceAuthEndpoint)
            .build()) {
      // primary
      EndpointProvider endpointProvider = env.getEndpointProvider();
      assertThat(endpointProvider.getResolvedTokenEndpoint()).isEqualTo(env.getTokenEndpoint());
      assertThat(endpointProvider.getResolvedAuthorizationEndpoint())
          .isEqualTo(env.getAuthorizationEndpoint());
      if (includeDeviceAuthEndpoint) {
        assertThat(endpointProvider.getResolvedDeviceAuthorizationEndpoint())
            .isEqualTo(env.getDeviceAuthorizationEndpoint());
      } else {
        assertThatThrownBy(endpointProvider::getResolvedDeviceAuthorizationEndpoint)
            .isInstanceOf(IllegalStateException.class)
            .hasMessage(
                "OpenID provider metadata does not contain a device authorization endpoint");
      }
      // impersonation
      endpointProvider = env.getImpersonatinEndpointProvider();
      assertThat(endpointProvider.getResolvedTokenEndpoint())
          .isEqualTo(env.getImpersonationTokenEndpoint());
      assertThat(endpointProvider.getResolvedAuthorizationEndpoint())
          .isEqualTo(env.getAuthorizationEndpoint());
      if (includeDeviceAuthEndpoint) {
        assertThat(endpointProvider.getResolvedDeviceAuthorizationEndpoint())
            .isEqualTo(env.getDeviceAuthorizationEndpoint());
      } else {
        assertThatThrownBy(endpointProvider::getResolvedDeviceAuthorizationEndpoint)
            .isInstanceOf(IllegalStateException.class)
            .hasMessage(
                "OpenID provider metadata does not contain a device authorization endpoint");
      }
    }
  }

  @ParameterizedTest
  @CsvSource({
    "''              , /.well-known/openid-configuration",
    "/               , /.well-known/openid-configuration",
    "''              , /.well-known/oauth-authorization-server",
    "/               , /.well-known/oauth-authorization-server",
    "/realms/master  , /realms/master/.well-known/openid-configuration",
    "/realms/master/ , /realms/master/.well-known/openid-configuration",
    "/realms/master  , /realms/master/.well-known/oauth-authorization-server",
    "/realms/master/ , /realms/master/.well-known/oauth-authorization-server"
  })
  void fetchOpenIdProviderMetadataSuccess(String contextPath, String wellKnownPath) {
    try (TestEnvironment env =
        TestEnvironment.builder()
            .authorizationServerContextPath(contextPath)
            .wellKnownPath(wellKnownPath)
            .impersonationEnabled(true)
            .impersonationServerContextPath(contextPath)
            .build()) {
      // primary
      EndpointProvider endpointProvider = env.getEndpointProvider();
      MetadataDiscoveryResponse actual = endpointProvider.getOpenIdProviderMetadata();
      assertThat(actual.getIssuerUrl()).isEqualTo(env.getAuthorizationServerUrl());
      assertThat(actual.getTokenEndpoint()).isEqualTo(env.getTokenEndpoint());
      assertThat(actual.getAuthorizationEndpoint()).isEqualTo(env.getAuthorizationEndpoint());
      assertThat(actual.getDeviceAuthorizationEndpoint())
          .isEqualTo(env.getDeviceAuthorizationEndpoint());
      // impersonation
      endpointProvider = env.getImpersonatinEndpointProvider();
      actual = endpointProvider.getOpenIdProviderMetadata();
      assertThat(actual.getIssuerUrl()).isEqualTo(env.getAuthorizationServerUrl());
      assertThat(actual.getTokenEndpoint()).isEqualTo(env.getTokenEndpoint());
      assertThat(actual.getAuthorizationEndpoint()).isEqualTo(env.getAuthorizationEndpoint());
      assertThat(actual.getDeviceAuthorizationEndpoint())
          .isEqualTo(env.getDeviceAuthorizationEndpoint());
    }
  }

  @Test
  void fetchOpenIdProviderMetadataWrongEndpoint() {
    try (TestEnvironment env = TestEnvironment.builder().createDefaultExpectations(false).build()) {
      env.createErrorExpectations();
      EndpointProvider endpointProvider = env.getEndpointProvider();
      Throwable e = catchThrowable(endpointProvider::getOpenIdProviderMetadata);
      assertThat(e)
          .isInstanceOf(RESTException.class)
          .hasMessageContaining("Failed to fetch OpenID provider metadata");
      // first well-known path
      assertThat(e.getCause())
          .asInstanceOf(throwable(OAuth2Exception.class))
          .hasMessageContaining("OAuth2 request failed: Invalid request")
          .extracting(OAuth2Exception::getErrorResponse)
          .extracting(ErrorResponse::type, ErrorResponse::code, ErrorResponse::message)
          .containsExactly("invalid_request", 401, "Invalid request");
      // second well-known path
      assertThat(e.getSuppressed())
          .singleElement()
          .asInstanceOf(throwable(OAuth2Exception.class))
          .hasMessageContaining("OAuth2 request failed: Invalid request")
          .extracting(OAuth2Exception::getErrorResponse)
          .extracting(ErrorResponse::type, ErrorResponse::code, ErrorResponse::message)
          .containsExactly("invalid_request", 401, "Invalid request");
    }
  }

  @Test
  void fetchOpenIdProviderMetadataWrongData() {
    try (TestEnvironment env = TestEnvironment.builder().createDefaultExpectations(false).build()) {
      ((UnitTestHttpServer) env.getServer())
          .getClientAndServer()
          .when(HttpRequest.request())
          .respond(
              HttpResponse.response()
                  .withStatusCode(200)
                  .withContentType(MediaType.APPLICATION_JSON)
                  .withBody(JsonBody.json(INVALID_METADATA)));
      EndpointProvider endpointProvider = env.getEndpointProvider();
      Throwable e = catchThrowable(endpointProvider::getOpenIdProviderMetadata);
      // first well-known path
      assertThat(e)
          .isInstanceOf(RESTException.class)
          .hasMessageContaining("Failed to fetch OpenID provider metadata");
      assertThat(e.getCause())
          .asInstanceOf(throwable(RESTException.class))
          .hasMessageContaining(
              "Received a success response code of 200, but failed to parse response body into MetadataDiscoveryResponse");
      // second well-known path
      assertThat(e.getSuppressed())
          .singleElement()
          .asInstanceOf(throwable(RESTException.class))
          .hasMessageContaining(
              "Received a success response code of 200, but failed to parse response body into MetadataDiscoveryResponse");
    }
  }
}
