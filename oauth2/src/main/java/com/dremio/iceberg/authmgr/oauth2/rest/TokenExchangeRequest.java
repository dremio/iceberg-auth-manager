/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.rest;

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.immutables.value.Value.Redacted;

/**
 * A <a href="https://datatracker.ietf.org/doc/html/rfc8693/#section-2.1">Token Exchange Request</a>
 * that is used to exchange an access token for a pair of access + refresh tokens.
 *
 * <p>Example:
 *
 * <pre>{@code
 * POST /as/token.oauth2 HTTP/1.1
 * Host: as.example.com
 * Authorization: Basic cnMwODpsb25nLXNlY3VyZS1yYW5kb20tc2VjcmV0
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
 * &resource=https%3A%2F%2Fbackend.example.com%2Fapi
 * &subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC
 * &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
 * }</pre>
 */
@AuthManagerImmutable
public abstract class TokenExchangeRequest implements TokenRequest {

  @Override
  public final GrantType getGrantType() {
    return GrantType.TOKEN_EXCHANGE;
  }

  /**
   * OPTIONAL. A URI that indicates the target service or resource where the client intends to use
   * the requested security token. This enables the authorization server to apply policy as
   * appropriate for the target, such as determining the type and content of the token to be issued
   * or if and how the token is to be encrypted.
   */
  @Nullable
  public abstract URI getResource();

  /**
   * OPTIONAL. The logical name of the target service where the client intends to use the requested
   * security token. This serves a purpose similar to the resource parameter but with the client
   * providing a logical name for the target service. Interpretation of the name requires that the
   * value be something that both the client and the authorization server understand.
   */
  @Nullable
  public abstract String getAudience();

  /**
   * OPTIONAL. An identifier, as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc8693/#section-3">Section 3</a>, for the type of
   * the requested security token. If the requested type is unspecified, the issued token type is at
   * the discretion of the authorization server and may be dictated by knowledge of the requirements
   * of the service or resource indicated by the resource or audience parameter.
   */
  @Nullable
  public abstract URI getRequestedTokenType();

  /**
   * A security token that represents the identity of the party on behalf of whom the request is
   * being made. Typically, the subject of this token will be the subject of the security token
   * issued in response to the request.
   */
  @Redacted
  public abstract String getSubjectToken();

  /**
   * An identifier, as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc8693/#section-3">Section 3</a>, that indicates
   * the type of the security token in the subject_token parameter.
   */
  public abstract URI getSubjectTokenType();

  /**
   * OPTIONAL. A security token that represents the identity of the acting party. Typically, this
   * will be the party that is authorized to use the requested security token and act on behalf of
   * the subject.
   */
  @Nullable
  @Redacted
  public abstract String getActorToken();

  /**
   * An identifier, as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc8693/#section-3">Section 3</a>, that indicates
   * the type of the security token in the actor_token parameter. This is REQUIRED when the
   * actor_token parameter is present in the request but MUST NOT be included otherwise.
   */
  @Nullable
  public abstract URI getActorTokenType();

  @Override
  public final Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>(TokenRequest.super.asFormParameters());
    if (getResource() != null) {
      data.put("resource", getResource().toString());
    }
    if (getAudience() != null) {
      data.put("audience", getAudience());
    }
    if (getRequestedTokenType() != null) {
      data.put("requested_token_type", getRequestedTokenType().toString());
    }
    data.put("subject_token", getSubjectToken());
    data.put("subject_token_type", getSubjectTokenType().toString());
    if (getActorToken() != null) {
      data.put("actor_token", getActorToken());
    }
    if (getActorTokenType() != null) {
      data.put("actor_token_type", getActorTokenType().toString());
    }
    return Map.copyOf(data);
  }

  public static Builder builder() {
    return ImmutableTokenExchangeRequest.builder();
  }

  public interface Builder
      extends TokenRequest.Builder<TokenExchangeRequest, Builder>,
          ClientRequest.Builder<TokenExchangeRequest, Builder> {

    @CanIgnoreReturnValue
    Builder resource(URI resource);

    @CanIgnoreReturnValue
    Builder audience(String audience);

    @CanIgnoreReturnValue
    Builder requestedTokenType(URI requestedTokenType);

    @CanIgnoreReturnValue
    Builder subjectToken(String subjectToken);

    @CanIgnoreReturnValue
    Builder subjectTokenType(URI subjectTokenType);

    @CanIgnoreReturnValue
    Builder actorToken(String actorToken);

    @CanIgnoreReturnValue
    Builder actorTokenType(URI actorTokenType);
  }
}
