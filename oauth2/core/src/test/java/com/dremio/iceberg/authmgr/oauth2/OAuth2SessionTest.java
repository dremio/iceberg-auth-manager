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
package com.dremio.iceberg.authmgr.oauth2;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_INITIAL;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.apache.iceberg.rest.HTTPHeaders.HTTPHeader;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.HTTPRequest.HTTPMethod;
import org.apache.iceberg.rest.ImmutableHTTPRequest;
import org.junit.jupiter.api.Test;

class OAuth2SessionTest {

  @Test
  void testDpop() throws Exception {
    try (TestEnvironment env = TestEnvironment.builder().dpopEnabled(true).build();
        OAuth2Session session = new OAuth2Session(env.getProperties(), env.getExecutor())) {

      URI rsUri = env.getCatalogServerUrl().resolve("v1/namespaces/ns/tables");
      HTTPRequest request =
          ImmutableHTTPRequest.builder().baseUri(rsUri).method(HTTPMethod.GET).path("").build();

      HTTPRequest authenticated = session.authenticate(request);

      // Authorization header uses DPoP scheme.
      assertThat(header(authenticated, "Authorization")).isEqualTo("DPoP " + ACCESS_TOKEN_INITIAL);

      // DPoP proof header is present, with correct htm/htu and ath bound to the access token.
      String dpopHeader = header(authenticated, "DPoP");
      assertThat(dpopHeader).isNotNull();

      JWTClaimsSet claims = SignedJWT.parse(dpopHeader).getJWTClaimsSet();
      assertThat(claims.getStringClaim("htm")).isEqualTo("GET");
      assertThat(claims.getStringClaim("htu")).isEqualTo(rsUri.toString());
      byte[] expectedHash =
          MessageDigest.getInstance("SHA-256")
              .digest(ACCESS_TOKEN_INITIAL.getBytes(StandardCharsets.US_ASCII));
      assertThat(claims.getStringClaim("ath")).isEqualTo(Base64URL.encode(expectedHash).toString());
    }
  }

  private static String header(HTTPRequest request, String name) {
    return request.headers().entries(name).stream().findFirst().map(HTTPHeader::value).orElse(null);
  }
}
